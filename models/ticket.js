const mongoose = require('mongoose');
const config = require('../config/database');
autoIncrement = require('mongoose-auto-increment')



// Ticket Schema
const TicketSchema = mongoose.Schema({
     userId: { type: String, required: true },
     subject: { type: String, required: true },
     priroty: { type: Number, min: 1, max: 5 },
     tokenType: { type: String, enum: ['Risky', 'Normal'] },
     description: { type: String, required: true },
     attachmentAddress: { type: String },
     createdate: { type: Date, default: Date.now() },
     lastReplayDate: { type: Date, default: Date.now() },
     recieveEmail: { type: Boolean, default: true },
     status: { type: String, enum: ['Open', 'Answered', 'Closed', 'Canceled'], default: 'Open' },
     replays: [{
          userId: { type: String, required: true },
          description: { type: String, required: true },
          replayDate: { type: Date, default: Date.now() }
     }]
});
TicketSchema.plugin(autoIncrement.plugin, { model: 'Ticket', field: 'ticketNumber', startAt: 100 });

const Ticket = module.exports = mongoose.model('Ticket', TicketSchema);

module.exports.addTicket = function (newTicket, callback) {
     newTicket.save(callback);
}