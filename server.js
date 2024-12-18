const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const session = require('express-session');
const cors = require('cors'); // Import CORS

// Initialize Express app
const app = express();
const port = 5000;

// Middleware
app.use(cors({ // Enable CORS for all origins
    origin: '*', // Change to specific origins if needed
    methods: ['GET', 'POST'], // Allowed HTTP methods
    allowedHeaders: ['Content-Type'], // Allowed headers
}));
app.use(bodyParser.json());
app.use(session({
    secret: 'your_secret_key',
    resave: false,
    saveUninitialized: true,
}));

// In-memory user data
let users = {
    'admin': {
        username: 'admin',
        passwordHash: bcrypt.hashSync('admin', 10), // Default password is 'admin'
    }
};

// Middleware to check authentication
function authenticate(req, res, next) {
    if (req.session && req.session.user) {
        next();
    } else {
        res.status(401).json({ message: 'Unauthorized. Please log in.' });
    }
}

// Login endpoint
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    // Check if user exists
    const user = users[username];
    if (!user) {
        return res.status(401).json({ message: 'Invalid username or password' });
    }

    // Validate password
    if (bcrypt.compareSync(password, user.passwordHash)) {
        req.session.user = user; // Store user in session
        res.json({ message: 'Login successful' });
    } else {
        res.status(401).json({ message: 'Invalid username or password' });
    }
});

// Password reset endpoint
app.post('/reset-password', authenticate, (req, res) => {
    const { oldPassword, newPassword, confirmNewPassword } = req.body;

    // Validate session user
    const user = req.session.user;

    // Check old password
    if (!bcrypt.compareSync(oldPassword, user.passwordHash)) {
        return res.status(400).json({ message: 'Old password is incorrect' });
    }

    // Check if new passwords match
    if (newPassword !== confirmNewPassword) {
        return res.status(400).json({ message: 'New passwords do not match' });
    }

    // Update password
    user.passwordHash = bcrypt.hashSync(newPassword, 10);
    users[user.username] = user; // Update in-memory user data
    res.json({ message: 'Password updated successfully' });
});

// Start server
app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});
