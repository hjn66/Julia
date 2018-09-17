const express = require("express");
const router = express.Router();
const passport = require("passport");
const randToken = require("rand-token");
const multer = require("multer");

const Log = require("../log");
const Ticket = require("../models/ticket");
const User = require("../models/user");
const Email = require("../config/email");

var storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "./uploads");
  },
  filename: function(req, file, cb) {
    raw = randToken.generate(16);
    cb(null, raw.toString("hex") + Date.now() + path.extname(file.originalname));
  }
});
var upload = multer({ storage: storage });

// Create new ticket
router.post("/create", passport.authenticate("jwt", { session: false }), upload.single("attachment"), (req, res, next) => {
  const userEmail = req.user.email;
  let newTicket = new Ticket({
    userEmail: userEmail,
    subject: req.body.subject,
    description: req.body.description,
    tokenType: req.body.tokenType,
    recieveEmail: req.body.recieveEmail
  });
  if (req.file) {
    newTicket.attachmentAddress = req.file.filename;
  }
  newTicket.save(function(err) {
    if (err) return res.json({ success: false, msg: "Error on save ticket" });
    Log("Method: CreateTicket, Info: Ticket Number " + newTicket.ticketNumber + " Created", req.user.email);
    res.json({ success: true, msg: "Ticket Number " + newTicket.ticketNumber + " Created" });
  });
});

// Cancel own ticket
router.post("/cancel", passport.authenticate("jwt", { session: false }), (req, res, next) => {
  const userEmail = req.user.email;
  const ticketNumber = req.body.ticketNumber;

  Ticket.getTicketByNumber(ticketNumber, (err, ticket) => {
    if (err) throw err;
    if (!ticket) {
      Log("Method: CancelTicket, Error: Ticket not found", req.user.email);
      return res.json({ success: false, msg: "Ticket not found" });
    }
    if (ticket.userEmail != userEmail) {
      Log("Method: CancelTicket, Error: User can not cancel others' ticket", req.user.email);
      res.json({ success: false, msg: "User can not cancel others' ticket" });
    } else {
      ticket.status = "Canceled";
      ticket.save(function(err) {
        if (err) return res.json({ success: false, msg: "Error on save ticket" });
        Log("Method: CancelTicket, Info: Ticket Number(" + ticketNumber + ") Canceled Successfuly", req.user.email);
        res.json({ success: true, msg: "Ticket Number(" + ticketNumber + ") Canceled Successfuly" });
      });
    }
  });
});

// Resolve own ticket
router.post("/resolve", passport.authenticate("jwt", { session: false }), (req, res, next) => {
  const userEmail = req.user.email;
  const ticketNumber = req.body.ticketNumber;

  Ticket.getTicketByNumber(ticketNumber, (err, ticket) => {
    if (err) throw err;
    if (!ticket) {
      Log("Method: ResolveTicket, Error: Ticket not found", req.user.email);
      return res.json({ success: false, msg: "Ticket not found" });
    }
    if (ticket.userEmail != userEmail) {
      Log("Method: ResolveTicket, Error: User can not resolve others' ticket", req.user.email);
      res.json({ success: false, msg: "User can not resolve others' ticket" });
    } else {
      ticket.status = "Closed";
      ticket.save(function(err) {
        if (err) return res.json({ success: false, msg: "Error on save ticket" });
        Log("Method: ResolveTicket, Info: Ticket Number(" + ticketNumber + ") Closed Successfuly", req.user.email);
        res.json({ success: true, msg: "Ticket Number(" + ticketNumber + ") Closed Successfuly" });
      });
    }
  });
});

// Replay own ticket
router.post("/replay", passport.authenticate("jwt", { session: false }), (req, res, next) => {
  const userEmail = req.user.email;
  const ticketNumber = req.body.ticketNumber;
  const replayDesc = req.body.replayDesc;

  Ticket.getTicketByNumber(ticketNumber, (err, ticket) => {
    if (err) throw err;
    if (!ticket) {
      Log("Method: ReplayTicket, Error: Ticket not found", req.user.email);
      return res.json({ success: false, msg: "Ticket not found" });
    }
    if (ticket.userEmail != userEmail) {
      Log("Method: ReplayTicket, Error: User can not replay others' ticket", req.user.email);
      res.json({ success: false, msg: "User can not replay others' ticket" });
    } else {
      let replay = { userEmail: userEmail, description: replayDesc };
      ticket.replays.push(replay);
      ticket.lastReplayDate = new Date();
      ticket.status = "Open";
      ticket.save(function(err) {
        if (err) return res.json({ success: false, msg: "Error on save ticket" });
        Log("Method: ReplayTicket, Info: Ticket Number(" + ticketNumber + ") Replayed Successfuly", req.user.email);
        res.json({ success: true, msg: "Ticket Number(" + ticketNumber + ") Replayed Successfuly" });
      });
    }
  });
});

// Answer ticket by admin
router.post("/answer", passport.authenticate("jwt", { session: false }), (req, res, next) => {
  const userEmail = req.user.email;
  const roles = req.user.roles;
  const ticketNumber = req.body.ticketNumber;
  const answerDesc = req.body.answerDesc;

  Ticket.getTicketByNumber(ticketNumber, (err, ticket) => {
    if (err) throw err;
    if (!ticket) {
      Log("Method: AnswerTicket, Error: Ticket not found", req.user.email);
      return res.json({ success: false, msg: "Ticket not found" });
    }
    User.hasRole(roles, ["admin", "answerTicket"], hasRole => {
      if (!hasRole) {
        Log("Method: AnswerTicket, Error: User has not permission to answer tickets", req.user.email);
        return res.sendStatus(401);
      } else {
        let replay = { userEmail: userEmail, description: answerDesc };
        ticket.replays.push(replay);
        ticket.lastReplayDate = new Date();
        ticket.status = "Answered";
        ticket.save(function(err) {
          // if ticket.reciveEmail == true then send email to user and notify about answer ticket
          if (ticket.recieveEmail) {
            var mailContent = "Hi <br>";
            mailContent += "Ticket number(" + ticket.ticketNumber + ") with subject " + ticket.subject;
            mailContent += " answered by admin.<br>";
            mailContent += "Admin's answer is: '" + answerDesc + "'";
            Email.sendMail(ticket.userEmail, "Your ticket answered", mailContent, (error, info) => {
              if (error) {
                Log("Method: AnswerTicket, Error: " + err + " while Sending Email to " + ticket.userEmail, req.user.email);
              } else {
                Log("Method: AnswerTicket, Info: Answer Ticket Email sent to " + ticket.userEmail, req.user.email);
              }
            });
          }
          if (err) return res.json({ success: false, msg: "Error on save ticket" });
          Log("Method: AnswerTicket, Info: Ticket Number(" + ticketNumber + ") Answered Successfuly", req.user.email);
          res.json({ success: true, msg: "Ticket Number(" + ticketNumber + ") Answered Successfuly" });
        });
      }
    });
  });
});

// List All tickets , all Status By Admin
router.get("/listall", passport.authenticate("jwt", { session: false }), (req, res, next) => {
  const roles = req.user.roles;
  User.hasRole(roles, ["admin", "answerTicket"], hasRole => {
    if (!hasRole) {
      Log("Method: ListAllTicketByAdmin, Error: User has not permission to list all tickets", req.user.email);
      return res.sendStatus(401);
    } else {
      Ticket.getAllTicket("", "", (err, tickets) => {
        Log("Method: ListAllTicketByAdmin, Info: Admin Gets All Tickets", req.user.email);
        return res.json({ success: true, tickets: tickets });
      });
    }
  });
});

// List All Open tickets By Admin
router.get("/listallopen", passport.authenticate("jwt", { session: false }), (req, res, next) => {
  const roles = req.user.roles;
  User.hasRole(roles, ["admin", "answerTicket"], hasRole => {
    if (!hasRole) {
      Log("Method: ListAllOpenTicketByAdmin, Error: User has not permission to list all tickets", req.user.email);
      return res.sendStatus(401);
    } else {
      Ticket.getAllTicket("", "Open", (err, tickets) => {
        Log("Method: ListAllOpenTicketByAdmin, Info: Admin Gets All Tickets", req.user.email);
        return res.json({ success: true, tickets: tickets });
      });
    }
  });
});

// List All tickets , all Status By User
router.get("/listmy", passport.authenticate("jwt", { session: false }), (req, res, next) => {
  const userEmail = req.user.email;

  Ticket.getAllTicket(userEmail, "", (err, tickets) => {
    Log("Method: ListAllTicketByUser, Info: User Gets All Own Tickets", req.user.email);
    return res.json({ success: true, tickets: tickets });
  });
});

// List Open tickets By User
router.get("/listmyopen", passport.authenticate("jwt", { session: false }), (req, res, next) => {
  const userEmail = req.user.email;

  Ticket.getAllTicket(userEmail, "Open", (err, tickets) => {
    Log("Method: ListAllOpenTicketByUser, Info: User Gets Own Open Tickets", req.user.email);
    return res.json({ success: true, tickets: tickets });
  });
});

module.exports = router;
