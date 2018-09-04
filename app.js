const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const cors = require('cors');
const passport = require('passport');
const mongoose = require('mongoose');
const config = require('./config/database');
const configAdmin = require('./config/admin');


mongoose.connect(config.database, { useNewUrlParser: true });
mongoose.set('useCreateIndex', true)


mongoose.connection.on('connected', () => {
     console.log('Connetcted to DB');
});

// Database connection Error
mongoose.connection.on('error', console.error.bind(console, 'connection error:'));

const app = express();

const users = require('./routes/users');

const port = 3000;

// CORS Middleware
app.use(cors());

// Set Static Folder
app.use(express.static(path.join(__dirname, 'public')));

// Body Parser Middleware
app.use(bodyParser.json());

// Passport Middleware
app.use(passport.initialize());
app.use(passport.session());

require('./config/passport')(passport);

app.use('/users', users);

app.get('/', (req, res) => {
     res.send('Invalid');
});

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

app.listen(port, () => {
     console.log('Server started on ' + port);
});