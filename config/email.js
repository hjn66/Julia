var nodemailer = require('nodemailer');

const emailUsername = 'Citex2018@gmail.com';
const emailPassword = 'Hojjat@1397';

module.exports.sendMail = function (emailTo, emailSubject, emailContent, callback) {
     var transporter = nodemailer.createTransport({
          service: 'gmail',
          auth: {
               user: emailUsername,
               pass: emailPassword
          }
     });
     var mailContent = emailContent;
     var mailOptions = {
          from: emailUsername,
          to: emailTo,
          subject: emailSubject,
          html: mailContent
     };
     transporter.sendMail(mailOptions, callback);
}