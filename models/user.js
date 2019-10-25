const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const randToken = require("rand-token");

// User Schema
const UserSchema = mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true },
  emailVerified: { type: Boolean, default: false },
  emailVerificationToken: { type: String },
  password: { type: String, required: true },
  KYCVerified: { type: Boolean, default: false },
  KYCUpdated: { type: Boolean, default: false },
  SignedContract: { type: Boolean, default: false },
  enabled: { type: Boolean },
  firstName: { type: String },
  lastName: { type: String },
  birthDate: { type: String },
  address: { type: String },
  walletAddress: { type: String, lowercase: true },
  telephone: { type: String },
  passportImageAddress: { type: String },
  registeredDate: { type: Date, default: Date.now() },
  referal: { type: String },
  contractType: { type: String, enum: ["Risky", "Normal"] },
  roles: [{ roleTitle: String }]
});

UserSchema.index(
  { walletAddress: 1 },
  {
    unique: true,
    partialFilterExpression: { walletAddress: { $type: "string" } }
  }
);

const User = (module.exports = mongoose.model("User", UserSchema));

module.exports.getUserById = function(id, callback) {
  User.findById(id, callback);
};

module.exports.getUserByStrId = async function(strId) {
  letid = mongoose.Types.ObjectId;
  if (id.isValid(strId)) {
    id = mongoose.Types.ObjectId(strId);
    user = await User.findById(id);
    if (user) {
      return user;
    }
  }
  throw new Error("UserId not found");
};

module.exports.getUserByEmail = async function(email) {
  const query = { email: email };
  user = await User.findOne(query);

  if (!user) {
    throw new Error("Email not registered");
  }
  return user;
};

module.exports.addAdministrator = function(administrator, callback) {
  User.getUserByEmail(administrator.email, (err, admin) => {
    if (err) throw err;
    if (!admin) {
      bcrypt.genSalt(10, (err, salt) => {
        bcrypt.hash(administrator.password, salt, (err, hash) => {
          if (err) throw err;
          administrator.password = hash;
          administrator.KYCVerified = true;
          administrator.emailVerified = true;
          administrator.roles = [
            { roleTitle: "admin" },
            { roleTitle: "verifyKYC" },
            { roleTitle: "changeRoles" },
            { roleTitle: "answerTickets" },
            { roleTitle: "userManager" },
            { roleTitle: "RPCManager" }
          ];
          administrator.save(callback);
        });
      });
    }
  });
};

module.exports.addUser = async function(newUser) {
  salt = await bcrypt.genSalt(10);
  hash = await bcrypt.hash(newUser.password, salt);
  newUser.password = hash;
  lettoken = randToken.generate(16);
  newUser.emailVerificationToken = token;
  newUser.roles = [{ roleTitle: "user" }];
  try {
    return await newUser.save();
  } catch (ex) {
    if (ex.code == 11000) {
      throw new Error(newUser.email + " registered before");
    } else {
      throw ex;
    }
  }
};

module.exports.comparePassword = async function(candidatePassword, hash) {
  return await bcrypt.compare(candidatePassword, hash);
};

module.exports.changePassword = async function(user, newPassword) {
  salt = await bcrypt.genSalt(10);
  hash = await bcrypt.hash(newPassword, salt);
  user.password = hash;
  return await user.save();
};

module.exports.checkReferal = async function(referal) {
  if (referal) {
    try {
      await User.getUserByStrId(referal);
      return true;
    } catch (ex) {
      throw new Error("Invalid Referal");
    }
  } else {
    return true;
  }
};

module.exports.hasRole = async function(roles, requestedRole) {
  letisFound = false;
  requestedRole.push("admin");

  roles.forEach(function(role, index, array) {
    if (requestedRole.includes(role.roleTitle)) {
      isFound = true;
    }
  });
  return await isFound;
};

module.exports.getUserReferals = async function(id) {
  const query = { referal: id };
  return await User.find(query, callback);
};

module.exports.getUsersList = async function() {
  const query = {};
  return await User.find(query);
};

module.exports.getUsersListRoles = async function() {
  const query = {};
  return await User.find(query, {
    email: 1,
    firstName: 1,
    lastName: 1,
    roles: 1
  });
};

module.exports.getUsersListKYC = async function() {
  const query = { KYCUpdated: true, KYCVerified: false };
  return await User.find(query, {
    email: 1,
    firstName: 1,
    lastName: 1,
    birthDate: 1,
    address: 1,
    walletAddress: 1,
    telephone: 1,
    passportImageAddress: 1,
    registeredDate: 1
  });
};

module.exports.getUserKYC = async function(email) {
  const query = { email: email };

  return await User.findOne(query, { password: 0 });
};
