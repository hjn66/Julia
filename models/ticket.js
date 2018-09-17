const mongoose = require("mongoose");
const config = require("../config/setting");
autoIncrement = require("mongoose-auto-increment");
const Email = require("../config/email");
const Log = require("../log");

// Ticket Schema
const TicketSchema = mongoose.Schema({
  userEmail: { type: String, required: true },
  subject: { type: String, required: true },
  priroty: { type: Number, min: 1, max: 5 },
  tokenType: { type: String, enum: ["Risky", "Normal"] },
  description: { type: String, required: true },
  attachmentAddress: { type: String },
  createdate: { type: Date, default: Date.now() },
  lastReplayDate: { type: Date, default: Date.now() },
  recieveEmail: { type: Boolean, default: true },
  status: {
    type: String,
    enum: ["Open", "Answered", "Closed", "Canceled"],
    default: "Open"
  },
  replays: [
    {
      userEmail: { type: String, required: true },
      description: { type: String, required: true },
      replayDate: { type: Date, default: Date.now() }
    }
  ]
});
TicketSchema.plugin(autoIncrement.plugin, {
  model: "Ticket",
  field: "ticketNumber",
  startAt: 100
});

const Ticket = (module.exports = mongoose.model("Ticket", TicketSchema));

//Close Answered Tickets Older than times in seconds
closeOldAnsweredTickets();

module.exports.addTicket = function(newTicket, callback) {
  newTicket.save(callback);
};

// Get ticket by ticketNumber
module.exports.getTicketByNumber = function(ticketNumber, callback) {
  const query = { ticketNumber: ticketNumber };
  Ticket.findOne(query, callback);
};

// Checks Old Answered Ticket And Close Them
function closeOldAnsweredTickets() {
  var date = new Date() - config.AutoClodeTickets;
  providedDate = new Date(date);

  const query = { lastReplayDate: { $lt: providedDate }, status: "Answered" };

  Ticket.find(query, function(err, tickets) {
    if (err) throw err;
    tickets.forEach(ticket => {
      if (ticket.recieveEmail) {
        var mailContent = "Hi <br>";
        mailContent += "Ticket number(" + ticket.ticketNumber + ") with subject " + ticket.subject;
        mailContent += " closed authomatically because admin answered one weeks ago and you don't replay it.";
        Email.sendMail(ticket.userEmail, "Your ticket closed by system", mailContent, (error, info) => {
          if (error) {
            Log("Method: CloseTicketAuthomaticaly, Error: " + err + " while Sending Email to " + ticket.userEmail, "SYSTEM");
          } else {
            Log("Method: CloseTicketAuthomaticaly, Info: Close Ticket Authomatically Email sent to " + ticket.userEmail, "SYSTEM");
          }
        });
      }
      ticket.status = "Closed";
      ticket.save(function(err) {
        if (err) {
          Log("Method: CloseTicketAuthomaticaly, Error: " + err.message, "SYSTEM");
        }
        Log("Method: CloseTicketAuthomaticaly, Info: Ticket number(" + ticket.ticketNumber + ") Closed", "SYSTEM");
      });
    });
  });
  //Repeat Function every minute
  setTimeout(closeOldAnsweredTickets, 60000);
}

// Get All Tickets
// if reqUserEmail == null then return all userEmail else retuen user's ticket
// if reqStatus == null return all status
module.exports.getAllTicket = function(reqUserEmail, reqStatus, callback) {
  var query = {};

  if (reqUserEmail) {
    query["userEmail"] = reqUserEmail;
  }
  if (reqStatus) {
    query["status"] = reqStatus;
  }

  // const query = { ticketNumber: ticketNumber }
  Ticket.find(query, callback);
};
