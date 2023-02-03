const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const User = require('./models/user'); // User model
const app = express();

// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/mydatabase', { useNewUrlParser: true, useUnifiedTopology: true });

// Middleware to parse request body
app.use(express.json());

// Route to handle user sign up
app.post('/signup', (req, res) => {
  // Check if username or email already exists
  User.findOne({ $or: [{ username: req.body.username }, { email: req.body.email }] }, (err, user) => {
    if (user) {
      return res.status(409).json({
        message: 'Username or email already exists'
      });
    }

    // Hash password before saving user
    bcrypt.hash(req.body.password, 10, (err, hash) => {
      if (err) {
        return res.status(500).json({
          error: err
        });
      }

      // Create new user
      const newUser = new User({
        username: req.body.username,
        email: req.body.email,
        password: hash
      });

      // Save user to database
      newUser.save((err, result) => {
        if (err) {
          return res.status(500).json({
            error: err
          });
        }

        res.status(201).json({
          message: 'User created successfully'
        });
      });
    });
  });
});

// Route to handle user login
app.post('/login', (req, res) => {
  // Find user by username or email
  User.findOne({ $or: [{ username: req.body.username }, { email: req.body.username }] }, (err, user) => {
    if (!user) {
      return res.status(401).json({
        message: 'Username or email not found'
      });
    }

    // Compare password with hashed password in database
    bcrypt.compare(req.body.password, user.password, (err, result) => {
      if (!result) {
        return res.status(401).json({
          message: 'Incorrect password'
        });
      }

      // Create JSON Web Token
      const token = jwt.sign({
        username: user.username,
        userId: user._id
      }, 'secret', {
        expiresIn: '1h'
      });

      res.status(200).json({
        message: 'Login successful',
        token: token
      });
    });
  });
});

// Start server
app.listen(3000, () => {
  console.log('Server started on port 3000');
});
