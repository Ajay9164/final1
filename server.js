// Import required modules
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config(); // To load environment variables
const cookieParser = require("cookie-parser");

// Initialize the Express app
const app = express();
const PORT = process.env.PORT || 5000; // Default to port 5000 or use environment variable for production

app.use(cookieParser());

// Middleware to parse JSON data
app.use(bodyParser.json());

// Enable CORS
app.use(cors());

// Connect to MongoDB (Digital Ocean Cloud MongoDB)
const mongoose = require('mongoose');
const mongoURI = process.env.MONGO_URI; // Get the MongoDB URI from .env file

mongoose
  .connect(mongoURI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(async (data) => {
    console.log("Connected to MongoDB");
    console.log("Host:", data.connection.host);
    console.log("Database Name:", data.connection.name);

    const collections = await data.connection.db.listCollections().toArray();
    const collectionNames = collections.map((collection) => collection.name);
    console.log("Collections:", collectionNames);
  })
  .catch((err) => console.error("MongoDB connection error:", err));

// Define a User schema with bcryptjs for password hashing
const userSchema = new mongoose.Schema({
  userId: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

// Pre-save hook to hash password before saving it to DB
userSchema.pre('save', async function(next) {
  if (this.isModified('password')) {
    this.password = await bcrypt.hash(this.password, 10);
  }
  next();
});

const User = mongoose.models.User || mongoose.model('User', userSchema);

// Register API Endpoint
app.post('/register', async (req, res) => {
  const { userId, password } = req.body;

  // Validate input
  if (!userId || !password) {
    return res.status(400).json({ message: 'User ID and password are required.' });
  }

  try {
    // Check if userId already exists
    const existingUser = await User.findOne({ userId });
    if (existingUser) {
      return res.status(400).json({ message: 'User ID already exists. Please choose another one.' });
    }

    // Create a new user
    const newUser = await User.create({ userId, password });
    
    return res.status(201).json({ message: 'User registered successfully!' });
  } catch (err) {
    console.log(err);
    return res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Login API Endpoint
app.post('/login', async (req, res) => {
  const { userId, password } = req.body;

  // Validate input
  if (!userId || !password) {
    return res.status(400).json({ message: 'User ID and password are required.' });
  }

  try {
    // Find user by userId
    const user = await User.findOne({ userId });

    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials.' });
    }

    // Compare password with hashed password stored in DB
    const isMatch = await bcrypt.compare(password, user.password);
    
    if (isMatch) {
      // Generate JWT token
      const token = jwt.sign({ userId: user.userId }, 'your_jwt_secret_key', { expiresIn: '1h' });

      return res.status(200)
        .cookie("token", token, { httpOnly: true, secure: true })
        .json({ message: 'Login successful!', token });
    } else {
      return res.status(401).json({ message: 'Invalid credentials.' });
    }
  } catch (err) {
    return res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Password Reset Endpoint
// Password Reset Endpoint
app.post('/reset-password', async (req, res) => {
  const { currentPassword, newPassword, confirmPassword } = req.body;

  // Validate input
  if (!currentPassword || !newPassword || !confirmPassword) {
    return res.status(400).json({ message: 'Current password, new password, and confirm password are required.' });
  }

  // Check if newPassword and confirmPassword match
  if (newPassword !== confirmPassword) {
    return res.status(400).json({ message: 'New password and confirm password do not match.' });
  }

  try {
    // Get the user from the JWT token or from the database
    const token = req.cookies.token;  // Assuming you're storing the token in a cookie
    if (!token) {
      return res.status(401).json({ message: 'Unauthorized access. No token provided.' });
    }

    // Verify the JWT token and extract userId
    const decoded = jwt.verify(token, 'your_jwt_secret_key');
    const userId = decoded.userId;

    // Find user by userId
    const user = await User.findOne({ userId });
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    // Compare the current password with the one stored in the database
    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Current password is incorrect.' });
    }

    // Hash the new password and update it
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    await user.save();

    return res.status(200).json({ message: 'Password reset successfully!' });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: 'Server error', error: err.message });
  }
});


// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
