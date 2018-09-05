const express = require('express');
const router = express.Router();
const path = require('path');
const passport = require('passport');
const jwt = require('jsonwebtoken');
const config = require('../config/database');
const Email = require('../config/email');
const fs = require('fs');
const uploadDir = path.join(__dirname, '../uploads');
const User = require('../models/user');
const ForgottenPasswordToken = require('../models/forgotPassword');
const multer = require('multer');
const randToken = require('rand-token');
const Log = require('../log');

var storage = multer.diskStorage({
     destination: (req, file, cb) => {
          cb(null, './uploads')
     },
     filename: function (req, file, cb) {
          raw = randToken.generate(16)
          cb(null, raw.toString('hex') + Date.now() + path.extname(file.originalname));
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
                              Log("Method: RegisterUser, Error: Email registered before", newUser.email)
                              return res.json({ success: false, msg: 'Email registered before' });
                         } else {
                              Log("Method: RegisterUser, Error: " + err, newUser.email)
                              return res.json({ success: false, msg: err });
                         }
                    } else {
                         var mailContent = "<a>http://localhost:3000/users/verifyemail?email=" + user.email + "&verificationToken=" + user.emailVerificationToken + "</a>"
                         Email.sendMail(user.email, 'Verification Email', mailContent, (error, info) => {
                              if (error) {
                                   Log("Method: RegisterUser, Error: " + err + " while Sending Email", user.email);
                                   // console.log(error);
                              } else {
                                   Log("Method: RegisterUser, Message: Verification Email sent", user.email);
                                   // console.log('Verification Email sent: ' + info.response);
                              }
                         });
                         Log("Method: RegisterUser, Message: User registered successfuly", user.email);
                         return res.json({ success: true, msg: 'User registered successfuly' });
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
               Log("Method: Authenticate, Error: User not found", email)
               return res.json({ success: false, msg: 'User not found' });
          }
          if (!user.emailVerified) {
               Log("Method: Authenticate, Error: Email not verified", email)
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
                    Log("Method: Authenticate, Message: User authenticated successfuly", email)
                    return res.json({
                         success: true,
                         token: 'JWT ' + token,
                         user: {
                              id: user._id,
                              firstName: user.firstName,
                              lastName: user.lastName,
                              email: user.email,
                              roles: user.roles,
                              walletAddress: user.walletAddress,
                              telephone: user.telephone,
                              address: user.address,
                              passportImageAddress: user.passportImageAddress,
                              KYCVerified: user.KYCVerified
                         }
                    })
               } else {
                    Log("Method: Authenticate, Error: Wrong Password", email)
                    return res.json({ success: false, msg: 'Wrong Password' });
               }
          });
     });
});

// Profile
router.get('/profile', passport.authenticate('jwt', { session: false }), (req, res, next) => {
     return res.json({ user: req.user });
});

// Verify Email
router.get('/verifyemail', (req, res, next) => {
     const verificationToken = req.query.verificationToken;
     const email = req.query.email;
     User.getUserByEmail(email, (err, user) => {
          if (err) throw err;
          if (!user) {
               Log("Method: VerifyEmail, Error: User not found", email)
               return res.json({ success: false, msg: 'User not found' });
          }
          if (user.emailVerificationToken != verificationToken) {
               Log("Method: VerifyEmail, Error: Wrong Token", email)
               return res.json({ success: false, msg: 'Wrong Token' });
          } else {
               user.emailVerified = true;
               user.save();
               Log("Method: VerifyEmail, Message: Email Verified successfuly", email)
               return res.json({ success: true, msg: 'Email Verified successfuly' });
          }
     });
});

// Forgot Password
router.post('/forgotpassword', (req, res, next) => {
     let passwordToken = new ForgottenPasswordToken({
          email: req.body.email
     })
     User.getUserByEmail(passwordToken.email, (err, user) => {
          if (err) throw err;
          if (!user) {
               Log("Method: ForgotPassword, Error: User not found", passwordToken.email)
               return res.json({ success: false, msg: 'User not found' });
          }

          ForgottenPasswordToken.forgotPassword(passwordToken, (err, token) => {
               if (err) {
                    throw err;
               } else {
                    var mailContent = "<a>http://localhost:3000/users/resetpassword?email=" + passwordToken.email + "&resetpasswordtoken=" + passwordToken.token + "</a>";
                    Email.sendMail(user.email, 'Reset Password', mailContent, (error, info) => {
                         if (error) {
                              Log("Method: ForgotPassword, Error: " + err + " while Sending Email", user.email);
                              // console.log(error);
                         } else {
                              Log("Method: ForgotPassword, Message: Reset Password Email Email sent", user.email);
                              // console.log('Reset Password Email sent: ' + info.response);
                         }
                    });

                    return res.json({ success: true, msg: "Reset Password Email sent" });
               }
          });
     });
});

// Reset Password
router.post('/resetpassword', (req, res, next) => {
     const resetPassToken = req.body.resetpasswordtoken; + user.email
     const email = req.body.email;
     const password = req.body.password;

     ForgottenPasswordToken.getTokenByToken(resetPassToken, (err, token) => {
          if (err) throw err;
          if (!token || token.email != email) {
               Log("Method: PasswordReset, Error: Invalid Token", email)
               return res.json({ success: false, msg: 'Invalid Token' });
          } else {
               token.remove();
               if (token.expiration < Date.now()) {
                    Log("Method: PasswordReset, Error: Expired Token", email)
                    return res.json({ success: false, msg: 'Expired Token' });
               } else {
                    User.getUserByEmail(email, (err, user) => {
                         if (err) throw err;
                         if (!user) {
                              Log("Method: PasswordReset, Error: User not found", email)
                              return res.json({ success: false, msg: 'User not found' });
                         }
                         User.changePassword(user, password, (err, user) => {
                              if (err) {
                                   throw err;
                              }
                              Log("Method: PasswordReset, Message: Password reset successfuly", user.email)
                              return res.json({ success: true, msg: 'Password reset successfuly' });
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
     User.getUserByEmail(email, (err, user) => {
          if (err) throw err;
          if (!user) {
               Log("Method: ChangePassword, Error: User Not Found", email)
               return res.json({ success: false, msg: 'User not found' });
          }
          if (!user.emailVerified) {
               Log("Method: ChangePassword, Error: Email not verified", user.email)
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
                         Log("Method: ChangePassword, Message: Password changed successfuly", user.email)
                         return res.json({ success: true, msg: 'Password changed successfuly' });
                    });
               } else {
                    Log("Method: ChangePassword, Error: Wrong Old Password", user.email)
                    return res.json({ success: false, msg: 'Wrong Old Password' });
               }
          });
     });

});

// Update KYC
router.post('/updatekyc', passport.authenticate('jwt', { session: false }), upload.single('passportImage'), (req, res, next) => {
     const email = req.user.email;
     User.getUserByEmail(email, (err, user) => {
          if (err) throw err;
          if (!user) {
               Log("Method: UpdateKYC, Error: User Not Found", email)
               return res.json({ success: false, msg: 'User not found' });
          }
          user.firstName = req.body.firstName;
          user.lastName = req.body.lastName;
          user.birthDate = req.body.birthDate;
          user.walletAddress = req.body.walletAddress;
          user.telephone = req.body.telephone;
          user.address = req.body.address;
          if (user.passportImageAddress) {
               fs.unlink(uploadDir + "/" + user.passportImageAddress, (err) => {
                    if (err) throw err;
               });
          }
          if (req.file) {
               user.passportImageAddress = req.file.filename;
          }
          user.KYCVerified = false;
          user.save();
          Log("Method: UpdateKYC, Message: User KYC Updated", user.email)
          return res.json({ success: true, msg: "User KYC Updated" });
     });

});

// Verify KYC
router.post('/verifykyc', passport.authenticate('jwt', { session: false }), (req, res, next) => {
     const roles = req.user.roles;

     User.hasRole(roles, 'canVerifyKYC', (hasRole) => {
          if (!hasRole) {
               Log("Method: VerifyKYC, Error: User has not permission to verify KYC", user.email)
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
               User.getUserByEmail(email, (err, user) => {
                    if (err) throw err;
                    if (!user) {
                         Log("Method: VerifyKYC, Error: User(" + email + ") Not Found", req.user.email)
                         return res.json({ success: false, msg: 'User not found' });
                    }
                    if (verifyFirstName && verifyLastName && verifyBirthDate && verifyWallet && verifyAddress && verifyPassportImage && verifyTelephone) {
                         user.KYCVerified = true;
                         user.save();
                         var mailContent = "Hi " + user.firstName + "<br>";
                         mailContent += "Your KYC verified successfuly";
                         Email.sendMail(user.email, 'KYC Verifiation Successful', mailContent, (error, info) => {
                              if (error) {
                                   // console.log(error);
                                   Log("Method: VerifyKYC, Error: " + err + " while Sending Email to " + user.email, req.user.email);
                              } else {
                                   Log("Method: VerifyKYC, Message: KYC verifiation successful Email sent to " + user.email, req.user.email);
                              }
                         });
                         Log("Method: VerifyKYC, Message: User(" + user.email + ") KYC verified", req.user.email);
                         return res.json({ success: true, msg: 'User KYC verified' });
                    } else {
                         var mailContent = "Hi " + user.firstName + "<br>";
                         mailContent += "Your KYC not verified because: <ul>";
                         if (!verifyFirstName) {
                              mailContent += "<li>First Name Problem</li>";
                         }
                         if (!verifyLastName) {
                              mailContent += "<li>Last Name Problem</li>";
                         }
                         if (!verifyBirthDate) {
                              mailContent += "<li>BirthDate Problem</li>";
                         }
                         if (!verifyWallet) {
                              mailContent += "<li>Wallet Problem</li>";
                         }
                         if (!verifyAddress) {
                              mailContent += "<li>Address Problem</li>";
                         }
                         if (!verifyPassportImage) {
                              mailContent += "<li>PassportImage Problem</li>";
                         }
                         if (!verifyTelephone) {
                              mailContent += "<li>Telephone Problem</li>";
                         }
                         mailContent += "</ul>";

                         Email.sendMail(user.email, 'KYC Verifiation Failed', mailContent, (error, info) => {
                              if (error) {
                                   // console.log(error);
                                   Log("Method: VerifyKYC, Error: " + err + " while Sending Email to " + user.email, req.user.email);

                              } else {
                                   // console.log('KYC Verifiation failed Email sent: ' + info.response);
                                   Log("Method: VerifyKYC, Message: KYC verifiation failed Email sent to " + user.email, req.user.email);
                              }
                         });
                         Log("Method: VerifyKYC, Message: User(" + user.email + ") KYC not verified", req.user.email);
                         return res.json({ success: false, msg: 'User KYC not verified' });
                    }
               });

          }
     });
});

// Change Roles
router.post('/changeroles', passport.authenticate('jwt', { session: false }), (req, res, next) => {
     const adminRoles = req.user.roles;
     User.hasRole(adminRoles, 'canChangeRoles', (hasRole) => {
          if (!hasRole) {
               Log("Method: ChangeRoles, Error: User has not permission to change roles", req.user.email)
               return res.sendStatus(401);
          } else {
               const newRoles = req.body.roles;
               const email = req.body.email;
               User.getUserByEmail(email, (err, user) => {
                    if (err) throw err;
                    if (!user) {
                         Log("Method: ChangeRoles, Error: User(" + email + ") Not Found", req.user.email)
                         return res.json({ success: false, msg: 'User not found' });
                    }

                    user.roles = newRoles;
                    var roleStr = "";
                    newRoles.forEach(function (role, index, array) {
                         roleStr = roleStr + role.roleTitle + ",";
                    });
                    roleStr = roleStr.slice(0, -1);
                    user.save();
                    Log("Method: ChangeRoles, Message: Roles(" + roleStr + ") of User(" + email + ") changed successfuly", req.user.email)
                    return res.json({ success: true, msg: 'Roles change Successfuly' });
               });

          }
     });
});

// Change Roles
router.get('/getreferal', passport.authenticate('jwt', { session: false }), (req, res, next) => {
     const userId = req.user._id;
     User.getUserReferals(userId, (err, referals) => {
          if (err) throw err;
          var ReferedUsers = [];
          referals.forEach(function (referal, index, array) {
               ReferedUsers.push({ email: referal.email });
          })
          return res.json({ success: true, referals: ReferedUsers });
     });
});

// Get Users List
router.get('/list', passport.authenticate('jwt', { session: false }), (req, res, next) => {
     const roles = req.user.roles;

     User.hasRole(roles, 'admin', (hasRole) => {
          if (!hasRole) {
               Log("Method: VerifyKYC, Error: User has not permission to get users list", user.email)
               return res.sendStatus(401);
          } else {
               User.getUsersList((err, users) => {
                    if (err) throw err;
                    var usersList = [];
                    users.forEach(function (user, index, array) {
                         if (req.user.email != user.email)
                              usersList.push({ email: user.email, firstName: user.firstName, lastName: user.lastName, roles: user.roles });
                    })
                    return res.json({ success: true, users: usersList });
               });
          }
     });
});

module.exports = router;