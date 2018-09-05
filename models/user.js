const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const randToken = require('rand-token');


// User Schema
const UserSchema = mongoose.Schema({
     email: { type: String, required: true, unique: true, lowercase: true },
     emailVerified: { type: Boolean, default: false },
     emailVerificationToken: { type: String },
     password: { type: String, required: true },
     KYCVerified: { type: Boolean, default: false },
     firstName: { type: String },
     lastName: { type: String },
     birthDate: { type: String },
     address: { type: String },
     walletAddress: { type: String },
     telephone: { type: String },
     passportImageAddress: { type: String },
     registeredDate: { type: Date, default: Date.now() },
     referal: { type: String },
     roles: [{ roleTitle: String }]
});

const User = module.exports = mongoose.model('User', UserSchema);

module.exports.getUserById = function (id, callback) {
     User.findById(id, callback);
}

module.exports.getUserByEmail = function (email, callback) {
     const query = { email: email }
     User.findOne(query, callback);
}

module.exports.addAdministrator = function (administrator, callback) {
     User.getUserByEmail(administrator.email, (err, admin) => {
          if (err) throw err;
          if (!admin) {
               bcrypt.genSalt(10, (err, salt) => {
                    bcrypt.hash(administrator.password, salt, (err, hash) => {
                         if (err) throw err;
                         administrator.password = hash;
                         administrator.KYCVerified = true;
                         administrator.emailVerified = true;
                         administrator.roles = [{ roleTitle: "admin" }, { roleTitle: "canVerifyKYC" }, { roleTitle: "canChangeRoles" }];
                         administrator.save(callback);
                    });
               });
          }
     });

}

module.exports.addUser = function (newUser, callback) {
     bcrypt.genSalt(10, (err, salt) => {
          bcrypt.hash(newUser.password, salt, (err, hash) => {
               if (err) throw err;
               newUser.password = hash;
               var token = randToken.generate(16);
               newUser.emailVerificationToken = token;
               newUser.roles = [{ roleTitle: "user" }];
               newUser.save(callback);
          });
     });
}

module.exports.comparePassword = function (candidatePassword, hash, callback) {
     bcrypt.compare(candidatePassword, hash, (err, isMatch) => {
          if (err) throw err;
          callback(null, isMatch);
     });
}

module.exports.changePassword = function (user, newPassword, callback) {
     bcrypt.genSalt(10, (err, salt) => {
          bcrypt.hash(newPassword, salt, (err, hash) => {
               if (err) throw err;
               user.password = hash;
               user.save(callback);
          });
     });
}

module.exports.checkReferal = function (referal, callback) {
     if (referal) {
          var id = mongoose.Types.ObjectId;
          if (id.isValid(referal)) {
               id = mongoose.Types.ObjectId(referal);
               User.getUserById(id, (err, user) => {
                    if (err) throw err
                    if (!user) {
                         callback('Referal Not found', false);
                    } else {
                         callback(null, true);
                    }
               });
          } else {
               callback('Referal Not found', false);
          }
     } else {
          callback(null, true);
     }
}

module.exports.hasRole = function (roles, requestedRole, callback) {
     var isFound = false;
     roles.forEach(function (role, index, array) {
          if (role.roleTitle == requestedRole)
               isFound = true;
     })
     callback(isFound);
}

module.exports.getUserReferals = function (id, callback) {
     const query = { referal: id }
     User.find(query, callback);
}

module.exports.getUsersList = function (callback) {
     const query = { }
     User.find(query, callback);
}