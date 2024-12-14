// Import required modules
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');


// Initialize the Express app
const app = express();
const PORT = 5000;

// Middleware to parse JSON data
app.use(bodyParser.json());

// Enable CORS
app.use(cors());

// Connect to MongoDB (Digital Ocean Cloud MongoDB)

require('dotenv').config(); // This will load the .env file and make the variables available

const mongoose = require('mongoose');
const mongoURI = process.env.MONGO_URI; // Get the MongoDB URI from .env file

mongoose.connect(mongoURI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Connected to MongoDB'))
  .catch((err) => console.log('MongoDB connection error:', err));

  
// Define a User schema
const userSchema = new mongoose.Schema({
  userId: { type: String, required: true },
  password: { type: String, required: true },
});

const User = mongoose.model('User', userSchema);

// Seed default user into the database
(async () => {
  const existingUser = await User.findOne({ userId: 'Ajay' });
  if (!existingUser) {
    await User.create({ userId: 'Ajay', password: 'Ajay@9164' });
    console.log('Default user created');
  }
})();

// Login API endpoint
app.post('/login', async (req, res) => {
  const { userId, password } = req.body;

  // Validate input
  if (!userId || !password) {
    return res.status(400).json({ message: 'User ID and password are required.' });
  }

  // Check credentials
  try {
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
