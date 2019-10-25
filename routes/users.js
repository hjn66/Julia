const express = require("express");
const router = express.Router();
const path = require("path");
const passport = require("passport");
const jwt = require("jsonwebtoken");
const fs = require("fs");
const uploadDir = path.join(__dirname, "../uploads");
const multer = require("multer");
const randToken = require("rand-token");

const User = require("../models/user");
const Log = require("../middlewares/log");
const Email = require("../middlewares/email");
const config = require("../config/setting");
const rpcserver = require("../middlewares/rpcserver");
const ForgottenPasswordToken = require("../models/forgotPassword");
const autorize = require("../middlewares/authorize");

letstorage = multer.diskStorage({
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
letupload = multer({ storage: storage });

//Register
router.post("/", async (req, res, next) => {
  let newUser = new User({
    email: req.body.email,
    password: req.body.password,
    referal: req.body.referal
  });
  isValid = await User.checkReferal(newUser.referal);
  if (isValid) {
    user = await User.addUser(newUser);
    letmailContent = "Hi<br>";
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
    Email.sendMail(user.email, "Verification Email", mailContent);
    Log("Method: RegisterUser, Info: User registered successfuly", user.email);
    res.json({
      msg:
        "Your account created successfuly, please verify your email via verification link sent to your meilbox"
    });
    next();
  }
});

//Authenticate
router.post("/authenticate", async (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;

  user = await User.getUserByEmail(email);
  if (!user.emailVerified) {
    throw new Error("Email not verified");
  }

  isMatch = await User.comparePassword(password, user.password);
  if (isMatch) {
    const token = jwt.sign(user.toJSON(), config.secret, {
      expiresIn: 604800 // 1 week in sec
    });
    Log("Method: Authenticate, Info: User authenticated successfuly", email);
    user["password"] = "***";
    return res.json({
      success: true,
      token: "JWT " + token,
      user: user
    });
  } else {
    throw new Error("Wrong Password");
  }
});

// Verify Email
router.get("/verifyemail", async (req, res, next) => {
  const verificationToken = req.query.verificationToken;
  const email = req.query.email;
  user = await User.getUserByEmail(email);
  if (user.emailVerificationToken != verificationToken) {
    Log("Method: VerifyEmail, Error: Wrong Token", email);
    return res.redirect('/panel/#/login?msg="Email Not Verified, Wrong Token"');
  } else {
    user.emailVerified = true;
    await user.save();
    Log("Method: VerifyEmail, Info: Email Verified successfuly", email);
    return res.redirect('/panel/#/login?msg="Email Verified successfuly"');
  }
});

// Forgot Password
router.post("/forgotpassword", async (req, res, next) => {
  let passwordToken = new ForgottenPasswordToken({
    email: req.body.email
  });
  user = await User.getUserByEmail(passwordToken.email);
  passwordToken = await ForgottenPasswordToken.forgotPassword(passwordToken);
  letmailContent =
    '<a href="' +
    config.serverAddr +
    "users/resetpassword?email=" +
    passwordToken.email +
    "&resetpasswordtoken=" +
    passwordToken.token +
    '"Reset Password Link</a>';
  Email.sendMail(user.email, "Reset Password", mailContent);
  return res.json({ success: true, msg: "Reset Password Email sent" });
});

// Reset Password
router.post("/resetpassword", async (req, res, next) => {
  const resetPassToken = req.body.resetpasswordtoken;
  const email = req.body.email;
  const password = req.body.password;

  token = await ForgottenPasswordToken.getTokenByToken(resetPassToken);
  if (!token || token.email != email) {
    throw new Error("Invalid Token");
  } else {
    token.remove();
    if (token.expiration < Date.now()) {
      throw new Error("Expired Token");
    } else {
      user = await User.getUserByEmail(email);
      user = await User.changePassword(user, password);
      Log(
        "Method: PasswordReset, Info: Password reset successfuly",
        user.email
      );
      return res.json({
        success: true,
        msg: "Password reset successfuly"
      });
    }
  }
});

// Change Password
router.post(
  "/changepassword",
  passport.authenticate("jwt", { session: false }),
  async (req, res, next) => {
    const email = req.user.email;
    const oldPassword = req.body.oldPassword;
    const newPassword = req.body.newPassword;
    user = await User.getUserByEmail(email);
    if (!user.emailVerified) {
      throw new Error("Email not verified");
    }

    isMatch = await User.comparePassword(oldPassword, user.password);
    if (isMatch) {
      user = await User.changePassword(user, newPassword);
      Log(
        "Method: ChangePassword, Info: Password changed successfuly",
        user.email
      );
      return res.json({
        success: true,
        msg: "Password changed successfuly"
      });
    } else {
      throw new Error("Wrong Old Password");
    }
  }
);

// Update KYC
router.put(
  "/kyc",
  passport.authenticate("jwt", { session: false }),
  upload.single("passportImage"),
  async (req, res, next) => {
    const email = req.user.email;
    user = await User.getUserByEmail(email);
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
      console.log(req.file.originalname);
    }
    user.KYCUpdated = true;
    user.KYCVerified = false;
    try {
      return await user.save();
    } catch (ex) {
      if (ex.code == 11000) {
        throw new Error("Wallet address used by another user");
      } else {
        throw ex;
      }
    }

    Log("Method: UpdateKYC, Info: User KYC Updated", user.email);
    return res.json({ success: true, msg: "User KYC Updated" });
  }
);

// Verify KYC
router.post(
  "/verifykyc",
  [passport.authenticate("jwt", { session: false }), autorize],
  async (req, res, next) => {
    const roles = req.user.roles;

    hasRole = await User.hasRole(roles, ["verifyKYC"]);
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
      user = await User.getUserByEmail(email);
      if (
        verifyFirstName &&
        verifyLastName &&
        verifyBirthDate &&
        verifyWallet &&
        verifyAddress &&
        verifyPassportImage &&
        verifyTelephone
      ) {
        letmailContent = "Hi " + user.firstName + "<br>";
        mailContent += "Your KYC verified successfuly";
        Email.sendMail(user.email, "KYC Verifiation Successful", mailContent);

        user.KYCUpdated = false;
        user.KYCVerified = true;
        user.enabled = true;

        await user.save();
        Log(
          "Method: VerifyKYC, Info: User(" + user.email + ") KYC verified",
          req.user.email
        );
        return res.json({ success: true, msg: "User KYC verified" });
      } else {
        letmailContent = "Hi " + user.firstName + "<br>";
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

        Email.sendMail(user.email, "KYC Verifiation Failed", mailContent);

        user.KYCVerified = false;
        user.KYCUpdated = false;
        await user.save();
        Log(
          "Method: VerifyKYC, Info: User(" + user.email + ") KYC not verified",
          req.user.email
        );
        return res.json({ success: true, msg: "User KYC not verified" });
      }
    }
  }
);

// Disable User
router.post(
  "/disable",
  [passport.authenticate("jwt", { session: false }), autorize],
  async (req, res, next) => {
    const adminRoles = req.user.roles;
    hasRole = await User.hasRole(adminRoles, ["userManager"]);
    if (!hasRole) {
      Log(
        "Method: DisableUser, Error: User has not permission to disable users",
        req.user.email
      );
      return res.sendStatus(401);
    } else {
      const email = req.body.email;
      user = await User.getUserByEmail(email);
      user.enabled = false;

      rpcResponse = await rpcserver.removeFromWhiteList(
        user.walletAddress,
        referWallet
      );

      if (rpcResponse.success) {
        Log(
          "Method: DisableUser, Info: Wallet(" +
            user.walletAddress +
            ") removed from whitelist, txID: " +
            body.msg,
          "SYSTEM"
        );
        await user.save();
        Log(
          "Method: DisableUser, Info: User(" + email + ") disabled successfuly",
          req.user.email
        );
        return res.json({ success: true, msg: "User disabled successfuly" });
      } else {
        Log(
          "Method: DisableUser, Error: " +
            body.msg +
            "while remove wallet (" +
            user.walletAddress +
            ") from whitelist",
          "SYSTEM"
        );
        return res.json({ success: false, msg: rpcResponse.msg });
      }
    }
  }
);

// Sign Contract
router.post(
  "/sign-contract",
  passport.authenticate("jwt", { session: false }),
  async (req, res, next) => {
    const email = req.user.email;
    const contractType = req.body.contractType;
    user = await User.getUserByEmail(email);

    if (!user.KYCVerified) {
      Log("Method: SignContract, Error: KYC not verified yet", email);
      return res.json({
        success: false,
        msg:
          "KYC not verified, please update your KYC and wait to verify by admin"
      });
    } else {
      user.contractType = contractType;
      user.SignedContract = true;

      referal = await User.getUserByStrId(user.referal);
      referWallet = referal.walletAddress;
      rpcResponse = await rpcserver.addToWhiteList(
        user.walletAddress,
        referWallet
      );

      if (rpcResponse.success) {
        Log(
          "Method: SignContract, Info: Wallet(" +
            user.walletAddress +
            ") added to whitelist, txID: " +
            rpcResponse.msg,
          "SYSTEM"
        );
        await user.save();
        Log(
          "Method: SignContract, Info: Contract (" +
            contractType +
            ") signed by user",
          req.user.email
        );
        return res.json({ success: true, msg: "Contract Signed successfuly" });
      } else {
        Log(
          "Method: SignContract, Error: " +
            rpcResponse.msg +
            "while add wallet (" +
            user.walletAddress +
            ") to whitelist",
          "SYSTEM"
        );
        return res.json({ success: false, msg: rpcResponse.msg });
      }
    }
  }
);

// Enable User
router.post(
  "/enable",
  [passport.authenticate("jwt", { session: false }), autorize],
  async (req, res, next) => {
    const email = req.body.email;
    user = await User.getUserByEmail(email);
    user.enabled = true;

    rpcResponse = await rpcserver.addToWhiteList(user.walletAddress, null);

    if (rpcResponse.success) {
      Log(
        "Method: EnableUser, Info: Wallet(" +
          user.walletAddress +
          ") added to whitelist, txID: " +
          rpcResponse.msg,
        "SYSTEM"
      );
      await user.save();
      Log(
        "Method: EnableUser, Info: User(" + email + ") enabled successfuly",
        req.user.email
      );
      return res.json({ success: true, msg: "Contract Signed successfuly" });
    } else {
      Log(
        "Method: EnableUser, Error: " +
          rpcResponse.msg +
          "while add wallet (" +
          user.walletAddress +
          ") to whitelist",
        "SYSTEM"
      );
      return res.json({ success: false, msg: rpcResponse.msg });
    }
  }
);

// user, verifyKYC, changeRoles, answerTicket, userManager, RPCManager
// Change Roles
router.post(
  "/changeroles",
  [passport.authenticate("jwt", { session: false }), autorize],
  async (req, res, next) => {
    const email = req.body.email;
    if (req.body.email == req.user.email) {
      throw new Error("User can not change own role");
    } else {
      user = await User.getUserByEmail(email);
      hasAdminRole = await User.hasRole(user.roles, [""]);
      if (hasAdminRole) {
        throw new Error("Can not change admin roles");
      } else {
        const newRoles = [];
        if (req.body.user) {
          newRoles.push({ roleTitle: "user" });
        }
        if (req.body.verifyKYC) {
          newRoles.push({ roleTitle: "verifyKYC" });
        }
        if (req.body.changeRoles) {
          newRoles.push({ roleTitle: "changeRoles" });
        }
        if (req.body.changeRoles) {
          newRoles.push({ roleTitle: "answerTicket" });
        }
        if (req.body.changeRoles) {
          newRoles.push({ roleTitle: "userManager" });
        }
        if (req.body.changeRoles) {
          newRoles.push({ roleTitle: "RPCManager" });
        }
        user.roles = newRoles;
        letroleStr = "";
        newRoles.forEach(function(role, index, array) {
          roleStr = roleStr + role.roleTitle + ",";
        });
        roleStr = roleStr.slice(0, -1);
        await user.save();
        Log(
          "Method: ChangeRoles, Info: Roles(" +
            roleStr +
            ") of User(" +
            email +
            ") changed successfuly",
          req.user.email
        );
        return res.json({ success: true, msg: "Roles change Successfuly" });
      }
    }
  }
);

// Get Referals
router.get(
  "/getreferal",
  passport.authenticate("jwt", { session: false }),
  async (req, res, next) => {
    const userId = req.user._id;
    referals = await User.getUserReferals(userId);
    letReferedUsers = [];
    referals.forEach(function(referal, index, array) {
      ReferedUsers.push({ email: referal.email });
    });
    Log("Method: GetReferals, Info: Get Refeals successfuly", req.user.email);
    return res.json({ success: true, referals: ReferedUsers });
  }
);

// Get Users List for Change roles
router.get(
  "/listroles",
  [passport.authenticate("jwt", { session: false }), autorize],
  async (req, res, next) => {
    users = await User.getUsersListRoles();
    Log(
      "Method: GetUserListRoles, Info: Get users list successfuly",
      req.user.email
    );
    return res.json({ success: true, users: users });
  }
);

// Get Users List for KYC
router.get(
  "/listkyc",
  [passport.authenticate("jwt", { session: false }), autorize],
  async (req, res, next) => {
    users = await User.getUsersListKYC();
    Log(
      "Method: GetUserListKYC, Info: Get users list successfuly",
      req.user.email
    );
    return res.json({ success: true, users: users });
  }
);

// Get KYC informations of a user
router.post(
  "/get-kyc",
  [passport.authenticate("jwt", { session: false }), autorize],
  async (req, res, next) => {
    const email = req.body.email;

    user = await User.getUserKYC(email);
    Log(
      "Method: GetKYCInfo, Info: Get user KYC info successfuly",
      req.user.email
    );
    return res.json({ success: true, user: user });
  }
);

module.exports = router;
