const mongoose = require("mongoose");
const config = require("../config/setting");
autoIncrement = require("mongoose-auto-increment");
const User = require("../models/user");

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
      var id = mongoose.Types.ObjectId;
      // if ticket.reciveEmail == true then send email to user and notify about closed ticket
      if (ticket.recieveEmail && id.isValid(ticket.userId)) {
        id = mongoose.Types.ObjectId(ticket.userId);
        User.getUserById(id, (err, user) => {
          if (err) throw err;
          var mailContent = "Hi " + user.firstName + "<br>";
          mailContent +=
            "Ticket number(" +
            ticket.ticketNumber +
            ") with subject " +
            ticket.subject;
          mailContent +=
            " closed authomatically because admin answered one weeks ago and you don't replay it.";
          Email.sendMail(
            user.email,
            "Your ticket closed by system",
            mailContent,
            (error, info) => {
              if (error) {
                Log(
                  "Method: CloseTicketAuthomaticaly, Error: " +
                    err +
                    " while Sending Email to " +
                    user.email,
                  "SYSTEM"
                );
              } else {
                Log(
                  "Method: CloseTicketAuthomaticaly, Info: Close Ticket Authomatically Email sent to " +
                    user.email,
                  "SYSTEM"
                );
              }
            }
          );
        });
      }
      ticket.save();
      ticket.status = "Closed";
      console.log(ticket.ticketNumber + "Closed");
    });
  });
  //Repeat Function every minute
  setTimeout(closeOldAnsweredTickets, 60000);
}

// Get All Tickets
// if reqUserId == null then return all userId else retuen user's ticket
// if reqStatus == null return all status
module.exports.getAllTicket = function(reqUserEmail, reqStatus, callback) {
  var query = {};
  console.log(reqStatus + "userId" + reqUserEmail);

  if (reqUserId) {
    query["userEmail"] = reqUserEmail;
  }
  if (reqStatus) {
    query["status"] = reqStatus;
  }

  console.log(query);

  // const query = { ticketNumber: ticketNumber }
  Ticket.find(query, callback);
};
