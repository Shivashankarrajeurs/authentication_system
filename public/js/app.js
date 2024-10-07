const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const dotenv = require('dotenv');

dotenv.config();

const app = express();

// Middleware
app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
}));

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => console.log('Connected to MongoDB')).catch(err => console.log(err));

// User schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true },
  password: { type: String, required: true },
  role: { type: String, default: 'user' } // Optional role-based access control
});

const User = mongoose.model('User', userSchema);

// Routes

// Registration page
app.get('/register', (req, res) => {
  res.sendFile(__dirname + '/views/register.html');
});

// Registration logic
app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  const hashedPassword = await bcrypt.hash(password, 10);

  const newUser = new User({
    username,
    password: hashedPassword
  });

  await newUser.save();
  res.redirect('/login');
});

// Login page
app.get('/login', (req, res) => {
  res.sendFile(__dirname + '/views/login.html');
});

// Login logic
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  const user = await User.findOne({ username });

  if (user && await bcrypt.compare(password, user.password)) {
    req.session.userId = user._id;
    req.session.userRole = user.role; // Store user role in session
    res.redirect('/dashboard');
  } else {
    res.redirect('/login');
  }
});

// Middleware for authentication check
function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.redirect('/login');
  }
  next();
}

// Middleware for role-based access
function requireAdmin(req, res, next) {
  if (req.session.userRole !== 'admin') {
    return res.status(403).send('Access Denied');
  }
  next();
}

// Protected route (accessible only after authentication)
app.get('/dashboard', requireAuth, (req, res) => {
  res.send('Welcome to your dashboard');
});

// Admin route (accessible only by admin)
app.get('/admin', [requireAuth, requireAdmin], (req, res) => {
  res.send('Admin Panel');
});

// Logout logic
app.post('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.redirect('/dashboard');
    }
    res.clearCookie('connect.sid');
    res.redirect('/login');
  });
});

// Start the server
app.listen(process.env.PORT, () => {
  console.log(`Server running on port ${process.env.PORT}`);
});
