const express = require('express');
const router = express.Router();
const passport = require('passport');
const Ticket = require('../models/ticket');
const randToken = require('rand-token');
const multer = require('multer');
const Log = require('../log');


var storage = multer.diskStorage({
     destination: (req, file, cb) => {
          cb(null, './uploads')
     },
     filename: function (req, file, cb) {
          raw = randToken.generate(16)
          cb(null, raw.toString('hex') + Date.now() + path.extname(file.originalname));
     }
});
var upload = multer({ storage: storage });

// Create new ticket
router.post('/create', passport.authenticate('jwt', { session: false }), upload.single('attachment'), (req, res, next) => {
     const userId = req.user._id;
     let newTicket = new Ticket({
          userId: userId,
          subject: req.body.subject,
          description: req.body.description,
          tokenType: req.body.tokenType,
          recieveEmail: req.body.recieveEmail
     });
     if (req.file) {
          newTicket.attachmentAddress = req.file.filename;
     }
     newTicket.save(function (err) {
          if (err) return handleError(err);
          Log("Method: CreateTicket, Message: Ticket Number " + newTicket.ticketNumber + " Created", req.user.email)
          res.json({ success: true, msg: 'Ticket Number ' + newTicket.ticketNumber + ' Created' });
     });
});

// Cancel own ticket
router.post('/cancel', passport.authenticate('jwt', { session: false }), (req, res, next) => {
     const userId = req.user._id;
     // console.log(req.body);
     const ticketNumber = req.body.ticketNumber;

     Ticket.getTicketByNumber(ticketNumber, (err, ticket) => {
          if (err) throw err;
          if (!ticket) {
               Log("Method: CancelTicket, Error: Ticket not found", req.user.email)
               return res.json({ success: false, msg: 'Ticket not found' });
          }
          if (ticket.userId != userId) {
               Log("Method: CancelTicket, Error: User can not cancel others' ticket", req.user.email)
               res.json({ success: false, msg: "User can not cancel others' ticket" });
          } else {
               ticket.status = 'Canceled';
               ticket.save(function (err) {
                    if (err) return handleError(err);
                    Log("Method: CancelTicket, Message: Ticket Number(" + ticketNumber + ") Canceled Successfuly", req.user.email)
                    res.json({ success: true, msg: "Ticket Number(" + ticketNumber + ") Canceled Successfuly" });
               })
          }
     });
});


module.exports = router;