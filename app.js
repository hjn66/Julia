const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const cors = require('cors');
const passport = require('passport');
const mongoose = require('mongoose'), Schema = mongoose.Schema, autoIncrement = require('mongoose-auto-increment');
const config = require('./config/setting');
const configAdmin = require('./config/admin');


mongoose.connect(config.database, { useNewUrlParser: true });
mongoose.set('useCreateIndex', true)
autoIncrement.initialize(mongoose.connection);


mongoose.connection.on('connected', () => {
     console.log('Connetcted to DB');
});

// Database connection Error
mongoose.connection.on('error', console.error.bind(console, 'connection error:'));

const app = express();

const users = require('./routes/users');
const tickets = require('./routes/tickets');

const port = 3000;

// CORS Middleware
app.use(cors());

// Set Static Folder
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.static(path.join(__dirname, 'uploads')));

// Body Parser Middleware
app.use(bodyParser.json());

// Passport Middleware
app.use(passport.initialize());
app.use(passport.session());

require('./config/passport')(passport);

app.use('/users', users);
app.use('/tickets', tickets);

const User = require('./models/user');
let administrator = new User({
     email: configAdmin.email,
     password: configAdmin.pass,
     firstName: configAdmin.firstName,
     lastName: configAdmin.lastName
});

User.addAdministrator(administrator, (err, user) => {
     if (err) throw err
     // console.log(user);
});

// myFunc('1');
app.listen(port, () => {
     console.log('Server started on ' + port);
});

function myFunc(arg) {
     var date = new Date();
     // date.setDate(date.getDate() + 1);
     date -= (60 * 60 * 1000);
     console.log(date, new Date(date), new Date());
     setTimeout(myFunc, 1500, 'funky');
   }
   