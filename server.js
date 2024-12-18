const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
require('dotenv').config(); // To load environment variables
const cookieParser = require('cookie-parser');

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
userSchema.pre('save', async function (next) {
  if (this.isModified('password')) {
    this.password = await bcrypt.hash(this.password, 10);
  }
  next();
});

const User = mongoose.models.User || mongoose.model('User', userSchema);

// Create default user if it doesn't exist
const createDefaultUser = async () => {
  const user = await User.findOne({ userId: 'admin' });

  if (!user) {
    const defaultUser = new User({
      userId: 'admin',
      password: 'admin', // Default password
    });
    await defaultUser.save();
    console.log("Default admin user created.");
  }
};

createDefaultUser();

// Login API Endpoint
app.post('/login', async (req, res) => {
  const { userId, password } = req.body;

  // Validate input
  if (!userId || !password) {
    return res.status(400).json({ message: 'User ID and password are required.' });
  }

  try {
    // Only allow "admin" to log in
    if (userId !== 'admin') {
      return res.status(401).json({ message: 'Invalid username or password' });
    }

    // Find user by userId
    const user = await User.findOne({ userId: 'admin' });

    if (!user) {
      return res.status(401).json({ message: 'Invalid username or password' });
    }

    // Compare password with hashed password stored in DB
    const isMatch = await bcrypt.compare(password, user.password);
    
    if (isMatch) {
      return res.status(200).json({ message: 'Login successful' });
    } else {
      return res.status(401).json({ message: 'Invalid username or password' });
    }
  } catch (err) {
    return res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Password Reset API Endpoint
app.post('/reset-password', async (req, res) => {
  const { oldPassword, newPassword, confirmNewPassword } = req.body;

  // Validate input
  if (!oldPassword || !newPassword || !confirmNewPassword) {
    return res.status(400).json({ message: 'Old password, new password, and confirm new password are required.' });
  }

  // Check if the new password and confirm password match
  if (newPassword !== confirmNewPassword) {
    return res.status(400).json({ message: 'New passwords do not match.' });
  }

  try {
    // Only allow password reset for "admin"
    const user = await User.findOne({ userId: 'admin' });
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    // Check if the old password matches the stored password
    const isMatch = await bcrypt.compare(oldPassword, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Old password is incorrect.' });
    }

    // Check if the new password is the same as the old password
    if (oldPassword === newPassword) {
      return res.status(400).json({ message: 'New password cannot be the same as the old password.' });
    }

    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update the password in the database
    user.password = hashedPassword;
    await user.save();

    return res.status(200).json({ message: 'Password updated successfully!' });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
