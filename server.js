const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const session = require('express-session');
const cors = require('cors');
const Redis = require('redis');
const sessionRedis = require('connect-redis')(session);

// Create and configure Redis client
const redisClient = Redis.createClient({
    host: 'your-redis-server-host', // For example, 'localhost' or a Redis cloud service
    port: 6379, // Default Redis port
    password: 'your-redis-password', // If applicable (for cloud Redis)
});

// Initialize Express app
const app = express();
const port = 5000;

// Middleware
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type'],
}));
app.use(bodyParser.json());

// Use Redis for session storage
app.use(session({
    store: new sessionRedis({ client: redisClient }),
    secret: 'your_secret_key',
    resave: false,
    saveUninitialized: true,
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production', // Set to 'true' for HTTPS in production
    }
}));

// In-memory user data
let users = {
    'admin': {
        username: 'admin',
        passwordHash: bcrypt.hashSync('admin', 10),
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
        req.session.user = user;
        res.json({ message: 'Login successful' });
    } else {
        res.status(401).json({ message: 'Invalid username or password' });
    }
});

// Password reset endpoint
app.post('/reset-password', authenticate, (req, res) => {
    const { oldPassword, newPassword, confirmNewPassword } = req.body;
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
    users[user.username] = user;
    res.json({ message: 'Password updated successfully' });
});

// Start server
app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});
