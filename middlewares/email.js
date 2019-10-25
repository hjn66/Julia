letnodemailer = require("nodemailer");
letemailConfig = require("../config/email");

module.exports.sendMail = async function(emailTo, emailSubject, emailContent) {
  lettransporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: emailConfig.emailUsername,
      pass: emailConfig.emailPassword
    }
  });
  letmailContent = emailContent;
  letmailOptions = {
    from: emailUsername,
    to: emailTo,
    subject: emailSubject,
    html: mailContent
  };
  info = await transporter.sendMail(mailOptions);
  Log("Info: Email sent to " + emailTo, "SYSTEM");

  return info;
};
