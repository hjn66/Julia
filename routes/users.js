const express = require("express");
const router = express.Router();
const path = require("path");
const passport = require("passport");
const jwt = require("jsonwebtoken");
const fs = require("fs");
const uploadDir = path.join(__dirname, "../uploads");
const multer = require("multer");
const randToken = require("rand-token");
const request = require("request");

const User = require("../models/user");
const Log = require("../log");
const Email = require("../config/email");
const config = require("../config/setting");
const ForgottenPasswordToken = require("../models/forgotPassword");

var storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "./uploads");
  },
  filename: function(req, file, cb) {
    raw = randToken.generate(16);
    cb(
      null,
      raw.toString("hex") + Date.now() + path.extname(file.originalname)
    );
  }
});
var upload = multer({ storage: storage });

//Register
router.post("/register", (req, res, next) => {
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
            console.log(err);

            Log(
              "Method: RegisterUser, Error: Email registered before",
              newUser.email
            );
            return res.json({ success: false, msg: "Email registered before" });
          } else {
            Log("Method: RegisterUser, Error: " + err, newUser.email);
            return res.json({ success: false, msg: err });
          }
        } else {
          var mailContent = "Hi<br>";
          mailContent +=
            "Your account registered suuccesfuly. To verify that this email address belongs to you, verify your email address. You can do this here:<br>";
          mailContent +=
            '<a href="' +
            config.serverAddr +
            "/users/verifyemail?email=" +
            user.email +
            "&verificationToken=" +
            user.emailVerificationToken +
            '">Verifiy Email Address</a>';
          Email.sendMail(
            user.email,
            "Verification Email",
            mailContent,
            (error, info) => {
              if (error) {
                Log(
                  "Method: RegisterUser, Error: " +
                    err +
                    " while Sending Email",
                  user.email
                );
              } else {
                Log(
                  "Method: RegisterUser, Info: Verification Email sent",
                  user.email
                );
              }
            }
          );
          Log(
            "Method: RegisterUser, Info: User registered successfuly",
            user.email
          );
          return res.json({
            success: true,
            msg:
              "Your account created successfuly, please verify your email via verification link sent to your meilbox"
          });
        }
      });
    }
  });
});

//Authenticate
router.post("/authenticate", (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;

  User.getUserByEmail(email, (err, user) => {
    if (err) throw err;
    if (!user) {
      Log("Method: Authenticate, Error: User not found", email);
      return res.json({ success: false, msg: "User not found" });
    }
    if (!user.emailVerified) {
      Log("Method: Authenticate, Error: Email not verified", email);
      return res.json({ success: false, msg: "Email not verified" });
    }

    User.comparePassword(password, user.password, (err, isMatch) => {
      if (err) {
        throw err;
      }
      if (isMatch) {
        const token = jwt.sign(user.toJSON(), config.secret, {
          expiresIn: 604800 // 1 week in sec
        });
        Log(
          "Method: Authenticate, Info: User authenticated successfuly",
          email
        );
        return res.json({
          success: true,
          token: "JWT " + token,
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
        });
      } else {
        Log("Method: Authenticate, Error: Wrong Password", email);
        return res.json({ success: false, msg: "Wrong Password" });
      }
    });
  });
});

// Profile
router.get(
  "/profile",
  passport.authenticate("jwt", { session: false }),
  (req, res, next) => {
    return res.json({ user: req.user });
  }
);

// Verify Email
router.get("/verifyemail", (req, res, next) => {
  const verificationToken = req.query.verificationToken;
  const email = req.query.email;
  User.getUserByEmail(email, (err, user) => {
    if (err) throw err;
    if (!user) {
      Log("Method: VerifyEmail, Error: User not found", email);
      // return res.json({ success: false, msg: 'User not found' });
      return res.redirect('/login?msg="Email Not Found"');
    }
    if (user.emailVerificationToken != verificationToken) {
      Log("Method: VerifyEmail, Error: Wrong Token", email);
      // return res.json({ success: false, msg: 'Wrong Token' });
      return res.redirect(
        '/panel/#/login?msg="Email Not Verified, Wrong Token"'
      );
    } else {
      user.emailVerified = true;
      user.save(function(err) {
        if (err) return res.redirect('/panel/#/login?msg="user can not save"');
        Log("Method: VerifyEmail, Info: Email Verified successfuly", email);
        return res.redirect('/panel/#/login?msg="Email Verified successfuly"');
      });
    }
  });
});

// Forgot Password
router.post("/forgotpassword", (req, res, next) => {
  let passwordToken = new ForgottenPasswordToken({
    email: req.body.email
  });
  User.getUserByEmail(passwordToken.email, (err, user) => {
    if (err) throw err;
    if (!user) {
      Log("Method: ForgotPassword, Error: User not found", passwordToken.email);
      return res.json({ success: false, msg: "User not found" });
    }

    ForgottenPasswordToken.forgotPassword(passwordToken, (err, token) => {
      if (err) {
        throw err;
      } else {
        var mailContent =
          '<a href="' +
          config.serverAddr +
          "users/resetpassword?email=" +
          passwordToken.email +
          "&resetpasswordtoken=" +
          passwordToken.token +
          '"Reset Password Link</a>';
        Email.sendMail(
          user.email,
          "Reset Password",
          mailContent,
          (error, info) => {
            if (error) {
              Log(
                "Method: ForgotPassword, Error: " +
                  err +
                  " while Sending Email",
                user.email
              );
              // console.log(error);
            } else {
              Log(
                "Method: ForgotPassword, Info: Reset Password Email Email sent",
                user.email
              );
              // console.log('Reset Password Email sent: ' + info.response);
            }
          }
        );

        return res.json({ success: true, msg: "Reset Password Email sent" });
      }
    });
  });
});

// Reset Password
router.post("/resetpassword", (req, res, next) => {
  const resetPassToken = req.body.resetpasswordtoken;
  +user.email;
  const email = req.body.email;
  const password = req.body.password;

  ForgottenPasswordToken.getTokenByToken(resetPassToken, (err, token) => {
    if (err) throw err;
    if (!token || token.email != email) {
      Log("Method: PasswordReset, Error: Invalid Token", email);
      return res.json({ success: false, msg: "Invalid Token" });
    } else {
      token.remove();
      if (token.expiration < Date.now()) {
        Log("Method: PasswordReset, Error: Expired Token", email);
        return res.json({ success: false, msg: "Expired Token" });
      } else {
        User.getUserByEmail(email, (err, user) => {
          if (err) throw err;
          if (!user) {
            Log("Method: PasswordReset, Error: User not found", email);
            return res.json({ success: false, msg: "User not found" });
          }
          User.changePassword(user, password, (err, user) => {
            if (err) {
              throw err;
            }
            Log(
              "Method: PasswordReset, Info: Password reset successfuly",
              user.email
            );
            return res.json({
              success: true,
              msg: "Password reset successfuly"
            });
          });
        });
      }
    }
  });
});

// Change Password
router.post(
  "/changepassword",
  passport.authenticate("jwt", { session: false }),
  (req, res, next) => {
    const email = req.user.email;
    const oldPassword = req.body.oldPassword;
    const newPassword = req.body.newPassword;
    User.getUserByEmail(email, (err, user) => {
      if (err) throw err;
      if (!user) {
        Log("Method: ChangePassword, Error: User Not Found", email);
        return res.json({ success: false, msg: "User not found" });
      }
      if (!user.emailVerified) {
        Log("Method: ChangePassword, Error: Email not verified", user.email);
        return res.json({ success: false, msg: "Email not verified" });
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
            Log(
              "Method: ChangePassword, Info: Password changed successfuly",
              user.email
            );
            return res.json({
              success: true,
              msg: "Password changed successfuly"
            });
          });
        } else {
          Log("Method: ChangePassword, Error: Wrong Old Password", user.email);
          return res.json({ success: false, msg: "Wrong Old Password" });
        }
      });
    });
  }
);

// Update KYC
router.post(
  "/updatekyc",
  passport.authenticate("jwt", { session: false }),
  upload.single("passportImage"),
  (req, res, next) => {
    const email = req.user.email;
    User.getUserByEmail(email, (err, user) => {
      if (err) throw err;
      if (!user) {
        Log("Method: UpdateKYC, Error: User Not Found", email);
        return res.json({ success: false, msg: "User not found" });
      }
      user.firstName = req.body.firstName;
      user.lastName = req.body.lastName;
      user.birthDate = req.body.birthDate;
      user.walletAddress = req.body.walletAddress;
      user.telephone = req.body.telephone;
      user.address = req.body.address;
      if (user.passportImageAddress) {
        fs.unlink(uploadDir + "/" + user.passportImageAddress, err => {
          if (err) throw err;
        });
      }
      if (req.file) {
        user.passportImageAddress = req.file.filename;
      }
      user.KYCUpdated = true;
      user.KYCVerified = false;
      user.save(function(err) {
        if (err) return res.json({ success: true, msg: err });
        Log("Method: UpdateKYC, Info: User KYC Updated", user.email);
        return res.json({ success: true, msg: "User KYC Updated" });
      });
    });
  }
);

// Verify KYC
router.post(
  "/verifykyc",
  passport.authenticate("jwt", { session: false }),
  (req, res, next) => {
    const roles = req.user.roles;

    User.hasRole(roles, ["admin", "canVerifyKYC"], hasRole => {
      if (!hasRole) {
        Log(
          "Method: VerifyKYC, Error: User has not permission to verify KYC",
          user.email
        );
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
            Log(
              "Method: VerifyKYC, Error: User(" + email + ") Not Found",
              req.user.email
            );
            return res.json({ success: false, msg: "User not found" });
          }
          if (
            verifyFirstName &&
            verifyLastName &&
            verifyBirthDate &&
            verifyWallet &&
            verifyAddress &&
            verifyPassportImage &&
            verifyTelephone
          ) {
            var mailContent = "Hi " + user.firstName + "<br>";
            mailContent += "Your KYC verified successfuly";
            Email.sendMail(
              user.email,
              "KYC Verifiation Successful",
              mailContent,
              (error, info) => {
                if (error) {
                  // console.log(error);
                  Log(
                    "Method: VerifyKYC, Error: " +
                      err +
                      " while Sending Email to " +
                      user.email,
                    req.user.email
                  );
                } else {
                  Log(
                    "Method: VerifyKYC, Info: KYC verifiation successful Email sent to " +
                      user.email,
                    req.user.email
                  );
                }
              }
            );
            user.KYCUpdated = false;
            user.KYCVerified = true;
            var addr = config.RPCServer + "/api/rpc/add-to-whitelist";
            console.log(addr);

            request.post(addr, { json: { user: user.walletAddress } }, function(
              error,
              response,
              body
            ) {
              console.log(body);

              console.log(response.statusCode);
              if (!error && response.statusCode == 200) {
                console.log(body);
              }
            });
            //   request.post(
            //     config.RPCServer + "/api/rpc/add-to-whitelist",
            //     { json: { user: user.walletAddress } },
            //     function(error, response, body) {
            //       if (!error && response.statusCode == 200) {
            //         console.log(body);
            //       } else {
            //         Log("Method: VerifyKYC, Error: ", req.user.email);
            //         return res.json({
            //           success: false,
            //           msg: "RPC Server Not Available"
            //         });
            //       }
            //     }
            //   );
            user.save(function(err) {
              if (err)
                return res.json({ success: false, msg: "User can not save" });
              Log(
                "Method: VerifyKYC, Info: User(" +
                  user.email +
                  ") KYC verified",
                req.user.email
              );
              return res.json({ success: true, msg: "User KYC verified" });
            });
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

            Email.sendMail(
              user.email,
              "KYC Verifiation Failed",
              mailContent,
              (error, info) => {
                if (error) {
                  // console.log(error);
                  Log(
                    "Method: VerifyKYC, Error: " +
                      err +
                      " while Sending Email to " +
                      user.email,
                    req.user.email
                  );
                } else {
                  // console.log('KYC Verifiation failed Email sent: ' + info.response);
                  Log(
                    "Method: VerifyKYC, Info: KYC verifiation failed Email sent to " +
                      user.email,
                    req.user.email
                  );
                }
              }
            );

            user.KYCVerified = false;
            user.KYCUpdated = false;
            user.save(function(err) {
              if (err)
                return res.json({
                  success: false,
                  msg: "User can not Updated"
                });
              Log(
                "Method: VerifyKYC, Info: User(" +
                  user.email +
                  ") KYC not verified",
                req.user.email
              );
              return res.json({ success: true, msg: "User KYC Updated" });
            });
          }
        });
      }
    });
  }
);

// Change Roles
router.post(
  "/changeroles",
  passport.authenticate("jwt", { session: false }),
  (req, res, next) => {
    const adminRoles = req.user.roles;
    User.hasRole(adminRoles, ["admin", "canChangeRoles"], hasRole => {
      if (!hasRole) {
        Log(
          "Method: ChangeRoles, Error: User has not permission to change roles",
          req.user.email
        );
        return res.sendStatus(401);
      } else {
        // const newRoles = req.body.roles;
        const email = req.body.email;
        if (req.body.email == req.user.email) {
          Log(
            "Method: ChangeRoles, Error: User can not change own role",
            req.user.email
          );
          return res.json({
            success: false,
            msg: "User can not change own role"
          });
        } else {
          User.getUserByEmail(email, (err, user) => {
            if (err) throw err;
            if (!user) {
              Log(
                "Method: ChangeRoles, Error: User(" + email + ") Not Found",
                req.user.email
              );
              return res.json({ success: false, msg: "User not found" });
            }
            const newRoles = [];
            // if (req.body.admin) {
            //      newRoles.push({ roleTitle: "admin" })
            // }
            if (req.body.user) {
              newRoles.push({ roleTitle: "user" });
            }
            if (req.body.canVerifyKYC) {
              newRoles.push({ roleTitle: "canVerifyKYC" });
            }
            if (req.body.canChangeRoles) {
              newRoles.push({ roleTitle: "canChangeRoles" });
            }
            user.roles = newRoles;
            var roleStr = "";
            newRoles.forEach(function(role, index, array) {
              roleStr = roleStr + role.roleTitle + ",";
            });
            roleStr = roleStr.slice(0, -1);
            user.save();
            Log(
              "Method: ChangeRoles, Info: Roles(" +
                roleStr +
                ") of User(" +
                email +
                ") changed successfuly",
              req.user.email
            );
            return res.json({ success: true, msg: "Roles change Successfuly" });
          });
        }
      }
    });
  }
);

// Get Referals
router.get(
  "/getreferal",
  passport.authenticate("jwt", { session: false }),
  (req, res, next) => {
    const userId = req.user._id;
    User.getUserReferals(userId, (err, referals) => {
      if (err) throw err;
      var ReferedUsers = [];
      referals.forEach(function(referal, index, array) {
        ReferedUsers.push({ email: referal.email });
      });
      Log("Method: GetReferals, Info: Get Refeals successfuly", req.user.email);
      return res.json({ success: true, referals: ReferedUsers });
    });
  }
);

// Get Users List for Change roles
router.get(
  "/listroles",
  passport.authenticate("jwt", { session: false }),
  (req, res, next) => {
    const roles = req.user.roles;

    User.hasRole(roles, ["admin", "canChangeRoles"], hasRole => {
      if (!hasRole) {
        Log(
          "Method: GetUserListRoles, Error: User has not permission to get users list",
          user.email
        );
        return res.sendStatus(401);
      } else {
        User.getUsersList((err, users) => {
          if (err) throw err;
          var usersList = [];
          users.forEach(function(user, index, array) {
            if (req.user.email != user.email)
              usersList.push({
                email: user.email,
                firstName: user.firstName,
                lastName: user.lastName,
                roles: user.roles
              });
          });
          Log(
            "Method: GetUserListRoles, Info: Get users list successfuly",
            req.user.email
          );
          return res.json({ success: true, users: usersList });
        });
      }
    });
  }
);

// Get Users List for KYC
router.get(
  "/listkyc",
  passport.authenticate("jwt", { session: false }),
  (req, res, next) => {
    const roles = req.user.roles;

    User.hasRole(roles, ["admin", "canVerifyKYC"], hasRole => {
      if (!hasRole) {
        Log(
          "Method: GetUserListKYC, Error: User has not permission to get users list",
          req.user.email
        );
        return res.sendStatus(401);
      } else {
        User.getUsersListKYC((err, users) => {
          if (err) throw err;
          var usersList = [];
          users.forEach(function(user, index, array) {
            if (req.user.email != user.email)
              usersList.push({
                email: user.email,
                firstName: user.firstName,
                lastName: user.lastName,
                birthDate: user.birthDate,
                address: user.address,
                walletAddress: user.walletAddress,
                telephone: user.telephone,
                passportImageAddress: user.passportImageAddress,
                registeredDate: user.registeredDate
              });
          });
          Log(
            "Method: GetUserListKYC, Info: Get users list successfuly",
            req.user.email
          );
          return res.json({ success: true, users: usersList });
        });
      }
    });
  }
);

// Get Users List for KYC
router.get("/listTest", (req, res, next) => {
  return res.json({ success: false, checkFirstName: true });
});

module.exports = router;
