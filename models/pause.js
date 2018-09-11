const mongoose = require("mongoose");

// Ticket Schema
const PauseSchema = mongoose.Schema({
  isPause: { type: Boolean, required: true },
  Date: { type: Date, default: Date.now() }
});

PauseSchema.statics.findMax = function(callback) {
  this.findOne({}) // 'this' now refers to the Member class
    .sort("-Date")
    .exec(callback);
};

const Pause = (module.exports = mongoose.model("Pause", PauseSchema));
