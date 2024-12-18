const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const session = require('express-session');
const cors = require('cors');
const redis = require('redis');
const connectRedis = require('connect-redis');

// Create a Redis client
const redisClient = redis.createClient({
    host: 'your-redis-host',  // Replace with your Redis host
    port: 6379,               // Default Redis port
    password: 'your-redis-password',  // Replace with your Redis password, if applicable
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

// Initialize RedisStore
const RedisStore = connectRedis(session);

// Use Redis for session storage
app.use(session({
    store: new RedisStore({ client: redisClient }),
    secret: 'your_secret_key',  // Replace with your secret key
    resave: false,
    saveUninitialized: true,
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',  // Set to 'true' for HTTPS in production
    }
}));

// In-memory user data
let users = {
    'admin': {
        username: 'admin',
        passwordHash: bcrypt.hashSync('admin', 10),  // Default password hash for 'admin'
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
        req.session.user = user;  // Save user info in session
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
