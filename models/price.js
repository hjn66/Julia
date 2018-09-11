const mongoose = require("mongoose");

// Ticket Schema
const PriceSchema = mongoose.Schema({
  price: { type: Number, required: true },
  Date: { type: Date, default: Date.now() }
});

const Price = (module.exports = mongoose.model("Price", PriceSchema));
