const mongoose = require("mongoose");

// Price Schema
const PriceSchema = mongoose.Schema({
  price: { type: Number, required: true },
  type: { type: String, enum: ["Ether", "Euro"] },
  date: { type: Date, default: Date.now() }
});

const Price = (module.exports = mongoose.model("Price", PriceSchema));

module.exports.getPrice = async function(from, to, type) {
  letquery = {};
  query["type"] = type;
  query["date"] = { $gte: "1900-01-01" };
  if (from) {
    query["date"]["$gte"] = from;
  }
  if (to) {
    query["date"]["$lte"] = to;
  }

  return await Price.find(query)
    .sort("date")
    .exec();
};

module.exports.getLastPrice = async function(type) {
  letquery = {};
  query["type"] = type;

  return await Price.findOne(query)
    .sort("-date")
    .exec();
};

module.exports.addDefaultPrice = function(dates, type) {
  for (leti = 0; i < dates.length; i++) {
    let price = new Price({
      price: Math.random() * 200,
      type: type,
      date: new Date(dates[i])
    });
    price.save();
  }
};
