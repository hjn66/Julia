const express = require('express');
const router = express.Router();
const path = require('path');
const bodyParser = require('body-parser');
const passport = require('passport');
const jwt = require('jsonwebtoken');
const config = require('../config/database');
const Email = require('../config/email');
const fs = require('fs');
const uploadDir = path.join(__dirname, '../uploads');
const User = require('../models/user');
const ForgottenPasswordToken = require('../models/forgotPassword');
const dateformat = require('dateformat');
const multer = require('multer');

var stream = fs.createWriteStream("./logs/" + dateformat(new Date(), "yyyy-mm-dd") + ".log", { flags: 'a' });


function Log(message, actionBy) {
     stream.write(dateformat(new Date(), "yyyy-mm-dd HH:MM:ss.l - ") + actionBy + " - " + message + "\n");
     // stream.end();
     // console.log("-----" + new Date().toISOString() + action);
}

var storage = multer.diskStorage({
     destination: (req, file, cb) => {
          cb(null, 'uploads')
     },
     filename: (req, file, cb) => {
          cb(null, file.fieldname + '-' + Date.now())
     }
});
var upload = multer({ storage: storage });


//Register
router.post('/register', (req, res, next) => {
     let newUser = new User({
          email: req.body.email,
          password: req.body.password,
          referal: req.body.referal
     });
     User.checkReferal(newUser.referal, (err, isValid) => {
          if (err) {
               return res.json({ success: false, msg: err });
          }
          if (isValid) {
               User.addUser(newUser, (err, user) => {
                    if (err) {
                         if (err.code == "11000") {
                              return res.json({ success: false, msg: 'Email registered before' });
                         } else {
                              return res.json({ success: false, msg: err });
                         }
                    } else {
                         var mailContent = "<a>http://localhost:3000/users/verifyemail?email=" + user.email + "&verificationToken=" + user.emailVerificationToken + "</a>"
                         Email.sendMail(user.email, 'Verification Email', mailContent, (error, info) => {
                              if (error) {
                                   console.log(error);
                              } else {
                                   console.log('Verification Email sent: ' + info.response);
                              }
                         });
                         return res.json({ success: true, msg: 'User registered ' });
                    }
               });
          }
     });
});

//Authenticate
router.post('/authenticate', (req, res, next) => {
     const email = req.body.email;
     const password = req.body.password;

     User.getUserByEmail(email, (err, user) => {
          if (err) throw err;
          if (!user) {
               return res.json({ success: false, msg: 'User not found' });
          }
          if (!user.emailVerified) {
               return res.json({ success: false, msg: 'Email not verified' });
          }

          User.comparePassword(password, user.password, (err, isMatch) => {
               if (err) {
                    throw err;
               }
               if (isMatch) {
                    const token = jwt.sign(user.toJSON(), config.secret, {
                         expiresIn: 604800 // 1 week in sec
                    });
                    res.json({
                         success: true,
                         token: 'JWT ' + token,
                         user: {
                              id: user._id,
                              firstName: user.firstName,
                              lastName: user.lastName,
                              email: user.email,
                              roles: user.roles
                         }
                    })
               } else {
                    return res.json({ success: false, msg: 'Wrong Password' });
               }
          });
     });
});

// Profile
router.get('/profile', passport.authenticate('jwt', { session: false }), (req, res, next) => {
     return res.json({ user: req.user });
});

// Admin
router.get('/admin', passport.authenticate('jwt', { session: false }), (req, res, next) => {
     if (req.user.username == "admin") {
          return res.json({ user: req.user });

     } else {
          return res.sendStatus(401);
     }

});

// Validate Email
router.get('/verifyemail', (req, res, next) => {
     const verificationToken = req.query.verificationToken;
     const email = req.query.email;
     User.getUserByEmail(email, (err, user) => {
          if (err) throw err;
          if (!user) {
               return res.json({ success: false, msg: 'User not found' });
          }
          if (user.emailVerificationToken != verificationToken) {
               return res.json({ success: false, msg: 'Wrong Token' });
          } else {
               user.emailVerified = true;
               user.save();
               return res.json({ success: true, msg: 'Email Validated' });
          }
     });
});

// Forgot Password
router.post('/forgotpassword', (req, res, next) => {
     let passwordToken = new ForgottenPasswordToken({
          email: req.body.email
     })
     // console.log(req.body.email);
     User.getUserByEmail(passwordToken.email, (err, user) => {
          if (err) throw err;
          if (!user) {
               return res.json({ success: false, msg: 'User not found' });
          }

          ForgottenPasswordToken.forgotPassword(passwordToken, (err, token) => {
               if (err) {
                    throw err;
               } else {
                    var mailContent = "<a>http://localhost:3000/users/resetpassword?email=" + passwordToken.email + "&resetpasswordtoken=" + passwordToken.token + "</a>";
                    Email.sendMail(user.email, 'Reset Password', mailContent, (error, info) => {
                         if (error) {
                              console.log(error);
                         } else {
                              console.log('Reset Password sent: ' + info.response);
                         }
                    });

                    return res.json({ success: true, msg: "Reset Password Email sent" });
               }
          });
     });
});

// Reset Password
router.post('/resetpassword', (req, res, next) => {
     const resetPassToken = req.body.resetpasswordtoken;
     const email = req.body.email;
     const password = req.body.password;

     ForgottenPasswordToken.getTokenByToken(resetPassToken, (err, token) => {
          if (err) throw err;
          if (!token || token.email != email) {
               return res.json({ success: false, msg: 'Invalid Token' });
          } else {
               token.remove();
               if (token.expiration < Date.now()) {
                    return res.json({ success: false, msg: 'Expired Token' });
               } else {
                    User.getUserByEmail(email, (err, user) => {
                         if (err) throw err;
                         if (!user) {
                              return res.json({ success: false, msg: 'User not found' });
                         }
                         User.changePassword(user, password, (err, user) => {
                              if (err) {
                                   throw err;
                              }
                              return res.json({ success: true, msg: 'Password reset' });
                         });
                    });
               }
          }
     });
});

// Change Password
router.post('/changepassword', passport.authenticate('jwt', { session: false }), (req, res, next) => {
     const email = req.user.email;
     const oldPassword = req.body.oldPassword;
     const newPassword = req.body.newPassword;
     // console.log(req.body);
     User.getUserByEmail(email, (err, user) => {
          if (err) throw err;
          if (!user) {
               Log("Methode: ChangePassword, Error: User Not Found", email)
               return res.json({ success: false, msg: 'User not found' });
          }
          if (!user.emailVerified) {
               Log("Methode: ChangePassword, Error: Email not verified", user.email)
               return res.json({ success: false, msg: 'Email not verified' });
          }

          User.comparePassword(oldPassword, user.password, (err, isMatch) => {
               if (err) {
                    throw err;
               }
               if (isMatch) {
                    User.changePassword(user, newPassword, (err, user) => {
                         if (err) {
                              throw err;
                         }
                         Log("Methode: ChangePassword, Message: Password changed successfuly", user.email)
                         return res.json({ success: true, msg: 'Password changed successfuly' });
                    });
               } else {
                    Log("Methode: ChangePassword, Error: Wrong Old Password", user.email)
                    return res.json({ success: false, msg: 'Wrong Old Password' });
               }
          });
     });

});

// Update KYC
router.post('/updatekyc', passport.authenticate('jwt', { session: false }), upload.single('passportImage'), (req, res, next) => {
     const email = req.user.email;
     // console.log(req.body);
     User.getUserByEmail(email, (err, user) => {
          if (err) throw err;
          if (!user) {
               Log("Methode: UpdateKYC, Error: User Not Found", email)
               return res.json({ success: false, msg: 'User not found' });
          }
          user.firstName = req.body.firstName;
          user.lastName = req.body.lastName;
          user.birthDate = req.body.birthDate;
          user.walletAddress = req.body.walletAddress;
          user.telephone = req.body.telephone;
          user.address = req.body.address;
          if (user.passportImageAddress) {
               fs.unlink(user.passportImageAddress, (err) => {
                    if (err) throw err;
               });
          }
          if (req.file) {
               user.passportImageAddress = uploadDir + "/" + req.file.filename;
          }
          user.KYCVerified = false;
          user.save();
          Log("Methode: UpdateKYC, Message: User KYC Updated", user.email)
          return res.json({ success: true, msg: "User KYC Updated" });
     });

});

// Verify KYC
router.post('/verifykyc', passport.authenticate('jwt', { session: false }), (req, res, next) => {
     const roles = req.user.roles;
     // console.log(req.body);

     User.hasRole(roles, 'canVerifyKYC', (hasRole) => {
          if (!hasRole) {
               // console.log(hasRole);
               Log("Methode: VerifyKYC, Eroor: User has not permission to verify KYC", user.email)
               return res.sendStatus(401);
          } else {
               const verifyFirstName = req.body.verifyFirstName;
               const verifyLastName = req.body.verifyLastName;
               const verifyBirthDate = req.body.verifyBirthDate;
               const verifyWallet = req.body.verifyWallet;
               const verifyAddress = req.body.verifyAddress;
               const verifyPassportImage = req.body.verifyPassportImage;
               const verifyTelephone = req.body.verifyTelephone;
               const email = req.body.email;
               // console.log(req);
               User.getUserByEmail(email, (err, user) => {
                    if (err) throw err;
                    if (!user) {
                         Log("Methode: UpdateKYC, Error: User(" + email + ") Not Found", req.user.email)
                         return res.json({ success: false, msg: 'User not found' });
                    }
                    if (verifyFirstName && verifyLastName && verifyBirthDate && verifyWallet && verifyAddress && verifyPassportImage && verifyTelephone) {
                         user.KYCVerified = true;
                         user.save();
                         var mailContent = "Hi " + user.firstName + "<br>";
                         mailContent += "Your KYC verified successfuly";
                         Email.sendMail(user.email, 'KYC Verifiation Successful', mailContent, (error, info) => {
                              if (error) {
                                   console.log(error);
                              } else {
                                   console.log('KYC Verifiation Email sent: ' + info.response);
                                   Log("Methode: UpdateKYC, Message: KYC verifiation successful Email sent to " + user.email, req.user.email);
                              }
                         });
                         Log("Methode: UpdateKYC, Message: User(" + user.email + ") KYC verified", req.user.email);
                         return res.json({ success: true, msg: 'User KYC verified' });
                    } else {
                         var mailContent = "Hi " + user.firstName + "<br>";
                         mailContent += "Your KYC not verified because: <ul>";
                         if (!verifyFirstName){
                              mailContent += "<li>First Name Problem</li>";
                         }
                         mailContent += "</ul>";

                         Email.sendMail(user.email, 'KYC Verifiation Failed', mailContent, (error, info) => {
                              if (error) {
                                   console.log(error);
                              } else {
                                   console.log('KYC Verifiation failed Email sent: ' + info.response);
                                   Log("Methode: UpdateKYC, Message: KYC verifiation failed Email sent to " + user.email, req.user.email);
                              }
                         });
                         Log("Methode: UpdateKYC, Message: User(" + user.email + ") KYC not verified", req.user.email);
                         return res.json({ success: false, msg: 'User KYC not verified' });
                    }
                    //res.json({ success: true, msg: "User KYC Updated" });
               });

          }
     });


});

module.exports = router;