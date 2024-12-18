require('dotenv').config();  // Load environment variables from .env file

const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo'); // MongoDB session store

const app = express();
const port = process.env.PORT || 5000;

// Use the MONGO_URI from .env file
const mongoURI = process.env.MONGO_URI;

// Connect to MongoDB Atlas
mongoose.connect(mongoURI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log("MongoDB connected"))
.catch((err) => console.log("MongoDB connection error: ", err));

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session configuration using MongoDB store
app.use(session({
  secret: 'your-secret-key', // Change this to a more secure key in production
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: mongoURI, // MongoDB Atlas connection string for sessions
    collectionName: 'sessions' // Sessions will be stored in this collection
  }),
  cookie: {
    httpOnly: true,
    secure: false, // Set to true if using HTTPS
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// Simulated user data (in real scenarios, you'd fetch this from a database)
const users = {
  admin: { password: 'admin' }
};

// Login route
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  // Check if username exists and password matches
  if (users[username] && users[username].password === password) {
    req.session.user = username;
    return res.status(200).send('Logged in successfully');
  } else {
    return res.status(401).send('Invalid credentials');
  }
});

// Password reset route
app.post('/reset-password', (req, res) => {
  const { oldPassword, newPassword, confirmPassword } = req.body;

  // Check if the user is logged in
  if (!req.session.user) {
    return res.status(401).send('You need to login first');
  }

  // Check if old password matches
  if (users[req.session.user].password !== oldPassword) {
    return res.status(400).send('Old password is incorrect');
  }

  // Check if new password and confirm password match
  if (newPassword !== confirmPassword) {
    return res.status(400).send('New password and confirm password do not match');
  }

  // Update password
  users[req.session.user].password = newPassword;
  return res.status(200).send('Password updated successfully');
});

// Start server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
