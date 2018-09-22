const express = require("express");
const router = express.Router();
const passport = require("passport");

const Log = require("../log");
const Pause = require("../models/pause");
const Price = require("../models/price");
const User = require("../models/user");

router.get("/ispaused", passport.authenticate("jwt", { session: false }), (req, res, next) => {
  const roles = req.user.roles;
  const isPaused = req.body.isPaused;
  User.hasRole(roles, ["admin", "RPCManager"], hasRole => {
    if (!hasRole) {
      Log("Method: IsPaused, Error: User has not permission to Pause/Unpause", req.user.email);
      return res.sendStatus(401);
    } else {
      let newPause = new Pause({
        isPause: isPaused,
        date: Date.now()
      });
      newPause.save(function(err) {
        if (err) {
          Log("Method: IsPaused, Error: " + err.message, req.user.email);
          return res.json({ success: false, msg: "Error on save pause" });
        }
        if (isPaused) {
          Log("Method: IsPaused, Info: Application Paused", "");
          return res.json({ success: true, msg: "Application Paused" });
        } else {
          Log("Method: IsPaused, Info: Application Unpaused", "");
          return res.json({ success: true, msg: "Application Unpaused" });
        }
      });
    }
  });
});

router.post("/token-ether-price", passport.authenticate("jwt", { session: false }), (req, res, next) => {
  price = req.body.price;
  const roles = req.user.roles;
  User.hasRole(roles, ["admin", "RPCManager"], hasRole => {
    if (!hasRole) {
      Log("Method: SetPrice, Error: User has not permission to change price", req.user.email);
      return res.sendStatus(401);
    } else {
      let newPrice = new Price({
        price: price,
        type: "Ether",
        date: Date.now()
      });
      newPrice.save(function(err) {
        if (err) {
          Log("Method: SetPrice, Error: " + err.message, req.user.email);
          return res.json({ success: false, msg: "Error on save price" });
        }
        Log("Method: SetPrice, Info: New Price Added", "");
        return res.json({ success: true, msg: "New Ether-Price Saved" });
      });
    }
  });
});

router.post("/token-euro-price", passport.authenticate("jwt", { session: false }), (req, res, next) => {
  price = req.body.price;
  const roles = req.user.roles;
  User.hasRole(roles, ["admin", "RPCManager"], hasRole => {
    if (!hasRole) {
      Log("Method: SetPrice, Error: User has not permission to change price", req.user.email);
      return res.sendStatus(401);
    } else {
      let newPrice = new Price({
        price: price,
        type: "Euro",
        date: Date.now()
      });
      newPrice.save(function(err) {
        if (err) {
          Log("Method: SetPrice, Error: " + err.message, req.user.email);
          return res.json({ success: false, msg: "Error on save price" });
        }
        Log("Method: SetPrice, Info: New Price Added", "");
        return res.json({ success: true, msg: "New Euro-Price Saved" });
      });
    }
  });
});

router.post("/get-price", (req, res, next) => {
  from = req.body.from;
  to = req.body.to;
  type = req.body.type;
  // console.log(req.connection.remoteAddress);

  Price.getPrice(from, to, type, (err, prices) => {
    if (err) throw err;
    Log("Method: GetPrice, Info: Get price list", "");
    return res.json({ success: true, prices: prices });
  });
});

router.post("/get-last-price", (req, res, next) => {
  type = req.body.type;

  Price.getLastPrice(type, (err, price) => {
    if (err) throw err;
    Log("Method: GetLastPrice, Info: Get last price in " + type + "(" + price.price + ")", "");
    return res.json({ success: true, price: price });
  });
});

router.get("/get-last-price-ether", (req, res, next) => {
  type = "Ether";

  Price.getLastPrice(type, (err, price) => {
    if (err) throw err;
    Log("Method: GetLastPriceEther, Info: Get last price in Ether(" + price.price + ")", "");
    return res.json({ success: true, price: price });
  });
});

router.get("/get-last-price-euro", (req, res, next) => {
  type = "Euro";

  Price.getLastPrice(type, (err, price) => {
    if (err) throw err;
    Log("Method: GetLastPriceEther, Info: Get last price in Euro(" + price.price + ")", "");
    return res.json({ success: true, price: price });
  });
});

module.exports = router;
