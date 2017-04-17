var express = require('express');
var router = express.Router();
var passport = require('passport');
var bcrypt = require('bcryptjs');
var LocalStrategy = require('passport-local').Strategy;
mongoose = require('mongoose');
nev = require('email-verification')(mongoose);
var User = require('../models/user');
var async = require('async');
var crypto = require('crypto');
var nodemailer = require('nodemailer');
var generated=false;
var db = mongoose.connection;

// Register
router.get('/register', function (req, res) {
    res.render('register');
});

// Login
router.get('/login', function (req, res) {
    res.render('login');
});

// oops
router.get('/error', function (req, res) {
    res.render('oops');
});
router.get('/forgot', function (req, res) {
    res.render('forgot');
});


router.post('/forgot', function (req, res) {

        async.waterfall([
            function(done) {
                crypto.randomBytes(20, function(err, buf) {
                    var token = buf.toString('hex');
                    done(err, token);
                });
            },
            function(token, done) {
                User.findOne({ email: req.body.email }, function(err, user) {
                    if (!user) {
                        req.flash('error', 'No account with that email address exists.');
                        return res.redirect('/users/forgot');
                    }

                    user.resetPasswordToken = token;
                    user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
                    console.log(Date.now());

                    user.save(function(err) {
                        done(err, token, user);
                    });
                });
            },
            function(token, user, done) {
                var smtpTransport = nodemailer.createTransport(({
                    host: 'smtp.gmail.com',
                    port: 465,
                   // secureConnection: false,
                    auth: {
                        user: 'your email',
                        pass: 'your password'

                    }
                }));
                var mailOptions = {
                    to: user.email,
                    from: 'your email',
                    subject: 'Node.js Password Reset',
                    text: 'You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n' +
                    'Please click on the following link, or paste this into your browser to complete the process:\n\n' +
                    'http://' + req.headers.host + '/users/reset/' + token + '\n\n' +
                    'If you did not request this, please ignore this email and your password will remain unchanged.\n'
                };
                smtpTransport.sendMail(mailOptions, function(err) {
                    req.flash('success_msg', 'An e-mail has been sent to ' + user.email + ' with further instructions.');
                    res.redirect('/users/forgot');
                    done(err, 'done');
                });
            }
        ], function(err) {
            if (err) return next(err);
        });
});


router.get('/reset/:token', function(req, res) {
    User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function(err, user) {
        if (!user) {
            req.flash('error', 'Password reset token is invalid or has expired.');
            return res.redirect('/users/forgot');
        }
        res.render('reset', {
            user: req.user
        });
    });
});

router.post('/reset/:token', function(req, res) {
    async.waterfall([
        function(done) {
            User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function(err, user) {
                if (!user) {
                    req.flash('error', 'Password reset token is invalid or has expired.');
                    return res.redirect('back');
                }
                else
                {
                    bcrypt.genSalt(10, function (err, salt) {
                        bcrypt.hash(req.body.password, salt, function (err, hash) {

                            console.log("old pass"+user.password);
                            console.log("new hashed"+hash);
                            user.password = hash;
                            user.resetPasswordToken = undefined;
                            user.resetPasswordExpires = undefined;
                            console.log("newpass"+user.password);
                            console.log("new hashed"+hash);
                            user.save(function(err) {
                                req.logIn(user, function(err) {
                                    done(err, user);
                                });
                            });
                        });
                    });
                }



            });
        },
        function(user, done) {
            var smtpTransport = nodemailer.createTransport(({
                host: 'smtp.gmail.com',
                port: 465,
                auth: {
                    user: 'your email',
                    pass: 'your password'

                }
            }));
            var mailOptions = {
                to: user.email,
                from: 'passwordreset@demo.com',
                subject: 'Your password has been changed',
                text: 'Hello,\n\n' +
                'This is a confirmation that the password for your account ' + user.email + ' has just been changed.\n'
            };
            smtpTransport.sendMail(mailOptions, function(err) {
                req.flash('success', 'Success! Your password has been changed.');
                done(err);
            });
        }
    ], function(err) {
        res.redirect('/');
    });
});

// Register User
router.post('/register', function (req, res) {
    var name = req.body.name;
    var email = req.body.email;
    var username = req.body.username;
    var password = req.body.password;
    var password2 = req.body.password2;

    // Validation
    req.checkBody('name', 'Name is required').notEmpty();
    req.checkBody('email', 'Email is required').notEmpty();
    req.checkBody('email', 'Email is not valid').isEmail();
    req.checkBody('username', 'Username is required').notEmpty();
    req.checkBody('password', 'Password is required').notEmpty();
    req.checkBody('password2', 'Passwords do not match').equals(req.body.password);


    var errors = req.validationErrors();
    if (errors) {
        res.render('register', {
            errors: errors
        });
    }

    // get the credentials from request parameters or something
    myHasher = function (password, tempUserData, insertTempUser, callback) {
        bcrypt.genSalt(10, function (err, salt) {
            bcrypt.hash(password, salt, function (err, hash) {
                return insertTempUser(hash, tempUserData, callback);
            });
        });
    };

    nev.configure({
        verificationURL: 'http://localhost:3000/users/${URL}',
        URLLength: 48,

        // mongo-stuff
        persistentUserModel: User,
        //tempUserModel: User,
        tempUserCollection: 'temp',
        emailFieldName: 'email',
        passwordFieldName: 'password',
        URLFieldName: 'GENERATED_VERIFYING_URL',
        expirationTime: 86400,

        // emailing options
        transportOptions: {
            service: 'Gmail',
            auth: {
                user: 'your username',
                pass: 'your password'
            }
        },
        verifyMailOptions: {
            from: 'Do Not Reply <your email>',
            subject: 'Confirm your account',
            html: '<p>you have created an account @ inventORinvest successfully with username ${newuser.username} and password ${newuser.password}</p>' +
            '<p>Please verify your account by clicking <a href="${URL}">this link</a>. If you are unable to do so, copy and ' +
            'paste the following link into your browser:</p><p>${URL}</p><p>this link will be valid for 24 hours only</p>',
            text: 'Please verify your account by clicking the following link, or by copying and pasting it into your browser: ${URL}'
        },
        shouldSendConfirmation: true,
        confirmMailOptions: {
            from: 'Do Not Reply <user@gmail.com>',
            subject: 'Successfully verified!',
            html: '<p>Your account has been successfully verified.</p>',
            text: 'Your account has been successfully verified.'
        },
        hashingFunction: myHasher

    });

    var newuser = new User({
        username: username,
        password: password,
        name: name,
        email: email
    });
    // configuration options go here...

// generating the model, pass the User model defined earlier


    if (!generated) {
        nev.generateTempUserModel(User);
        generated = true;
    }


    nev.createTempUser(newuser, function (err, existingPersistentUser, newTempUser, URL) {
        // some sort of error
        if (err)
            res.redirect('/user/error');// handle error...

        // user already exists in persistent collection...
        if (existingPersistentUser) {
            console.log("the user is persistant");// handle user's existence... violently.
            req.flash('success_msg', 'an account is registered with this email , please login ');
            res.redirect('/users/login');

        }

            // a new user

        else if (newTempUser) {
            var URL = newTempUser[nev.options.URLFieldName];
            nev.sendVerificationEmail(newuser.email, URL, function (err, info) {

                if (err)
                {
                    res.redirect('/users/error');// handle error...
                    console.log(err);
                }

                else
                    {
                        console.log("verification mail was sent");// flash message of success
                        req.flash('success_msg', 'verification mail was sent');
                        res.redirect('/users/login');
                    }


            });

            // user already exists in temporary collection...
        } else {
            console.log("user is already in the temp database");// flash message of failure...
            req.flash('success_msg', 'your account exists but not yet verified , please verify the account');
            res.redirect('/users/error');
        }


// verification

        router.get('/' + URL, function (req, res) {
            nev.confirmTempUser(URL, function (err, user) {
                if (err)
                    res.redirect('/users/error');// handle error...

                // user was found!
                if (user) {
                    console.log('registered :)')
                    nev.sendConfirmationEmail(user['email_field_name'], function (err, info) {
                    });
                    req.flash('success_msg', 'your account has been verified , please login');
                    res.redirect('/users/login');
                }
                // user's data probably expired...
                else
                {
                    //res.redirect('/users/session expired');	//console.log('user session has expired');// redirect to sign-up
                    req.flash('success_msg', 'sorry , verification link has expired , please register again');
                    res.redirect('/users/error');
                }

            });
        });

    });


    /*function() {

    console.log(entered);
    var email = this.email;
    nev.resendVerificationEmail(email, function (err, userFound) {
        if (err)
            console.log('error45')// handle error...

        if (userFound)
            console.log('userfound')// email has been sent
        else
            console.log('failure2')// flash message of failure...
    });
    return false;

                }*/

});

passport.use(new LocalStrategy(
    function (username, password, done) {
        User.getUserByUsername(username, function (err, user) {
            if (err) throw err;
            if (!user) {
                return done(null, false, {message: 'Unknown User'});
            }

            User.comparePassword(password, user.password, function (err, isMatch) {
                if (err) throw err;
                if (isMatch) {
                    return done(null, user);
                } else {
                    return done(null, false, {message: 'Invalid password'});
                }
            });
        });
    }));

passport.serializeUser(function (user, done) {
    done(null, user.id);
});

passport.deserializeUser(function (id, done) {
    User.getUserById(id, function (err, user) {
        done(err, user);
    });
});

router.post('/login',
    passport.authenticate('local', {successRedirect: '/', failureRedirect: '/users/login', failureFlash: true}),
    function (req, res) {
        res.redirect('/');
    });

router.get('/logout', function (req, res) {
    req.logout();

    req.flash('success_msg', 'You are logged out');

    res.redirect('/users/login');
});

module.exports = router;
