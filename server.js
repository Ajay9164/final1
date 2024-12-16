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
app.post('/reset-password', async (req, res) => {
  const { userId, newPassword } = req.body;

  // Validate input
  if (!userId || !newPassword) {
    return res.status(400).json({ message: 'User ID and new password are required.' });
  }

  try {
    // Find user by userId
    const user = await User.findOne({ userId });
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update the password in the database
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
