const User = require("../models/user");
const Log = require("../middlewares/log");

module.exports = async function(req, res, next) {
  const adminRoles = req.user.roles;
  switch (req.orginalUrl) {
    case ("/users/get-kyc", "/users/listkyc", "/users/verifykyc"):
      role = ["verifyKYC"];
      break;
    case ("/users/listroles", "/users/changeroles"):
      role = ["changeRoles"];
      break;
    case ("/users/enable", "/users/disable"):
      role = ["userManager"];
      break;
    case ("/tickets/answer", "/tickets/listall"):
      role = ["answerTicket"];
      break;
    case ("/rpc/ispaused", "/rpc/token-ether-price", "/rpc/token-euro-price"):
      role = ["RPCManager"];
      break;
    default:
      role = [""];
  }
  hasRole = await User.hasRole(adminRoles, role);
  if (!hasRole) {
    Log("URL: " + req.originalUrl + ", Error: Unauthorized action", req.user.email);
    return res.sendStatus(401);
  } else {
    next();
  }
};
