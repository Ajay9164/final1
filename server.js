// Import required modules
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const mongoose = require('mongoose');
require('dotenv').config(); // Load environment variables from .env

// Initialize the Express app
const app = express();
const PORT = process.env.PORT || 5000; // Use PORT from environment variables or default to 5000

// Middleware to parse JSON data
app.use(bodyParser.json());

// Enable CORS
app.use(cors());

// Connect to MongoDB
const mongoURI = process.env.MONGO_URI; // Get the MongoDB URI from .env file
mongoose.connect(mongoURI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Connected to MongoDB'))
  .catch((err) => console.log('MongoDB connection error:', err));

// Define a User schema
const userSchema = new mongoose.Schema({
  userId: { type: String, required: true, unique: true }, // Ensure userId is unique
  password: { type: String, required: true },
});

const User = mongoose.model('User', userSchema);

// Register API endpoint (allows users to register with their own userId and password)
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
    const newUser = new User({ userId, password });
    await newUser.save();

    return res.status(201).json({ message: 'User registered successfully!' });
  } catch (err) {
    return res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Login API endpoint
app.post('/login', async (req, res) => {
  const { userId, password } = req.body;

  // Validate input
  if (!userId || !password) {
    return res.status(400).json({ message: 'User ID and password are required.' });
  }

  try {
    // Check credentials
    const user = await User.findOne({ userId, password });

    if (user) {
      return res.status(200).json({ message: 'Login successful!' });
    } else {
      return res.status(401).json({ message: 'Invalid credentials.' });
    }
  } catch (err) {
    return res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
