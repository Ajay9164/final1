const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const bodyParser = require("body-parser");
require("dotenv").config(); // Load environment variables

// Initialize app
const app = express();
app.use(bodyParser.json());

// MongoDB connection
const MONGO_URI = process.env.MONGO_URI;
mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log("Connected to MongoDB"))
    .catch((err) => console.error("MongoDB connection error:", err));

// User schema
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true }
});

const User = mongoose.model("User", userSchema);

// Simulated session storage (use proper session management in production)
let currentUser = null;

// Initialize admin user if not exists
const initializeAdmin = async () => {
    const existingAdmin = await User.findOne({ username: "admin" });
    if (!existingAdmin) {
        const hashedPassword = await bcrypt.hash("admin", 10);
        await User.create({ username: "admin", password: hashedPassword });
        console.log("Admin user initialized with default credentials.");
    }
};
initializeAdmin();

// Login API
app.post("/login", async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = await User.findOne({ username });
        if (!user) return res.status(404).json({ message: "User not found" });

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) return res.status(401).json({ message: "Invalid credentials" });

        // Set current user (for simplicity, no token used here)
        currentUser = user;
        res.status(200).json({ message: "Login successful" });
    } catch (err) {
        res.status(500).json({ message: "Internal server error", error: err.message });
    }
});

// Reset Password API (no username required)
app.post("/reset-password", async (req, res) => {
    const { oldPassword, newPassword, confirmNewPassword } = req.body;

    try {
        if (!currentUser) return res.status(401).json({ message: "Unauthorized. Please login first." });

        // Validate new password confirmation
        if (newPassword !== confirmNewPassword) {
            return res.status(400).json({ message: "New password and confirmation do not match" });
        }

        // Verify old password
        const isOldPasswordValid = await bcrypt.compare(oldPassword, currentUser.password);
        if (!isOldPasswordValid) return res.status(401).json({ message: "Old password is incorrect" });

        // Update password
        const hashedNewPassword = await bcrypt.hash(newPassword, 10);
        currentUser.password = hashedNewPassword;
        await currentUser.save();

        res.status(200).json({ message: "Password reset successful" });
    } catch (err) {
        res.status(500).json({ message: "Internal server error", error: err.message });
    }
});

// Start server
const PORT = 5000;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
