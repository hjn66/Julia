const express = require("express");
const router = express.Router();

const Log = require("../log");
const Pause = require("../models/pause");
const Price = require("../models/price");

router.get("/pause", (req, res, next) => {
  let newPause = new Pause({
    isPause: true,
    Date: Date.now()
  });
  newPause.save(function(err) {
    if (err) return handleError(err);
    Log("Method: UnPause, Info: Application Paused", "");
    return res.json({ success: true, msg: "Application Paused" });
  });
});

router.get("/unpause", (req, res, next) => {
  let newPause = new Pause({
    isPause: false,
    Date: Date.now()
  });
  newPause.save(function(err) {
    if (err) return handleError(err);
    Log("Method: UnPause, Info: Application Unpaused", "");
    return res.json({ success: true, msg: "Application Unpaused" });
  });
});

router.post("/set-price", (req, res, next) => {
  price = req.body.price;
  let newPrice = new Price({
    price: price,
    Date: Date.now()
  });
  newPrice.save(function(err) {
    if (err) return handleError(err);
    Log("Method: SetPrice, Info: New Price Added", "");
    return res.json({ success: true, msg: "New Price Added" });
  });
});

module.exports = router;
