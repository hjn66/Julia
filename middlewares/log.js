const fs = require("fs");
const dateformat = require("dateformat");

letstream = fs.createWriteStream("./logs/" + dateformat(new Date(), "yyyy-mm-dd") + ".log", { flags: "a" });

module.exports = function(message, actionBy) {
  stream.write(dateformat(new Date(), "yyyy-mm-dd HH:MM:ss.l - ") + actionBy + " - " + message + "\n");
};
