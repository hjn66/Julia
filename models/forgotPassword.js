const mongoose = require("mongoose");
const config = require("../config/setting");
const randToken = require("rand-token");

// Forgotten Password Schema
const ForgottenPasswordTokenSchema = mongoose.Schema({
  email: {
    type: String,
    required: true
  },
  token: {
    type: String,
    required: true
  },
  expiration: {
    type: Date,
    // 15 Minutes Later
    default: Date.now() + 15 * 60 * 1000
  }
});

const ForgottenPasswordToken = (module.exports = mongoose.model("ForgottenPasswordToken", ForgottenPasswordTokenSchema));

module.exports.forgotPassword = function(forgotPasswordToken, callback) {
  var token = randToken.generate(16);
  forgotPasswordToken.token = token;
  forgotPasswordToken.save(callback);
};

module.exports.getTokenByToken = function(givenToken, callback) {
  const query = { token: givenToken.token };
  ForgottenPasswordToken.findOne(query, callback);
};

module.exports.getTokenByToken = function(givenToken, callback) {
  // delete expired token
  ForgottenPasswordToken.deleteMany({ expiration: { $lt: Date.now() } }, function(err) {
    if (err) return null;
  });
  const query = { token: givenToken };
  ForgottenPasswordToken.findOne(query, callback);
};
