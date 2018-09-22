const mongoose = require("mongoose");

// Price Schema
const PriceSchema = mongoose.Schema({
  price: { type: Number, required: true },
  type: { type: String, enum: ["Ether", "Euro"] },
  date: { type: Date, default: Date.now() }
});

const Price = (module.exports = mongoose.model("Price", PriceSchema));

module.exports.getPrice = function(from, to, type, callback) {
  var query = {};
  query["type"] = type;
  query["date"] = { $gte: "1900-01-01" };
  if (from) {
    query["date"]["$gte"] = from;
  }
  if (to) {
    query["date"]["$lte"] = to;
  }

  // console.log(query);

  Price.find(query)
    .sort("date")
    .exec(callback);
};

module.exports.getLastPrice = function(type, callback) {
  var query = {};
  query["type"] = type;

  // console.log(query);

  Price.findOne(query)
    .sort("-date")
    .exec(callback);
};

module.exports.addDefaultPrice = function(dates, type) {
  for (var i = 0; i < dates.length; i++) {
    let price = new Price({
      price: Math.random() * 200,
      type: type,
      date: new Date(dates[i])
    });
    price.save();
  }
};
