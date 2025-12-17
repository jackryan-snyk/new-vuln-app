const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql');
const _ = require('lodash');
const serialize = require('serialize-javascript');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const path = require('path');

const app = express();
const PORT = 3000;

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Insecure: Hardcoded secret key
const SECRET_KEY = 'my-secret-key-12345';

// Insecure: Database connection without proper error handling
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'password',
  database: 'vulnerable_db'
});

// SAST Vulnerability 1: SQL Injection
app.get('/users', (req, res) => {
  const userId = req.query.id;
  // VULNERABLE: Direct string interpolation in SQL query
  const query = `SELECT * FROM users WHERE id = ${userId}`;
  
  db.query(query, (err, results) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(results);
  });
});

// SAST Vulnerability 2: SQL Injection with LIKE
app.get('/search', (req, res) => {
  const searchTerm = req.query.q;
  // VULNERABLE: SQL injection in LIKE clause
  const query = `SELECT * FROM products WHERE name LIKE '%${searchTerm}%'`;
  
  db.query(query, (err, results) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(results);
  });
});

// SAST Vulnerability 3: Cross-Site Scripting (XSS) - Reflected
app.get('/echo', (req, res) => {
  const userInput = req.query.message;
  // VULNERABLE: Direct output without sanitization
  res.send(`<h1>Your message: ${userInput}</h1>`);
});

// SAST Vulnerability 4: Cross-Site Scripting (XSS) - Stored (simulated)
app.post('/comment', (req, res) => {
  const comment = req.body.comment;
  // VULNERABLE: Storing user input without sanitization
  const query = `INSERT INTO comments (text) VALUES ('${comment}')`;
  
  db.query(query, (err) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json({ success: true, message: 'Comment saved' });
  });
});

// SAST Vulnerability 5: Insecure Deserialization
app.post('/deserialize', (req, res) => {
  const serialized = req.body.data;
  // VULNERABLE: Using eval() on user input
  try {
    const deserialized = eval('(' + serialized + ')');
    res.json({ result: deserialized });
  } catch (err) {
    res.status(400).json({ error: 'Invalid data' });
  }
});

// SAST Vulnerability 6: Prototype Pollution
app.post('/merge', (req, res) => {
  const userObj = req.body.obj;
  const defaultObj = { role: 'user' };
  // VULNERABLE: Using lodash merge without proper validation
  const merged = _.merge(defaultObj, userObj);
  res.json(merged);
});

// SAST Vulnerability 7: Insecure JWT Secret
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  
  // VULNERABLE: Weak secret and no expiration
  const token = jwt.sign({ username }, SECRET_KEY);
  res.json({ token });
});

// SAST Vulnerability 8: Server-Side Request Forgery (SSRF)
app.get('/fetch', (req, res) => {
  const url = req.query.url;
  // VULNERABLE: Fetching user-provided URL without validation
  axios.get(url)
    .then(response => {
      res.json({ data: response.data });
    })
    .catch(err => {
      res.status(500).json({ error: err.message });
    });
});

// SAST Vulnerability 9: Command Injection
app.post('/ping', (req, res) => {
  const host = req.body.host;
  // VULNERABLE: Command injection via child_process
  const { exec } = require('child_process');
  exec(`ping -c 4 ${host}`, (error, stdout, stderr) => {
    if (error) {
      return res.status(500).json({ error: error.message });
    }
    res.send(`<pre>${stdout}</pre>`);
  });
});

// SAST Vulnerability 10: Path Traversal
app.get('/file', (req, res) => {
  const filename = req.query.name;
  // VULNERABLE: Path traversal attack
  const fs = require('fs');
  const filePath = path.join(__dirname, 'uploads', filename);
  
  fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.send(data);
  });
});

// SAST Vulnerability 11: Insecure Random Number Generation
app.get('/token', (req, res) => {
  // VULNERABLE: Using Math.random() for security-sensitive operations
  const token = Math.random().toString(36).substring(2, 15);
  res.json({ token });
});

// SAST Vulnerability 12: Hardcoded Credentials
app.post('/admin', (req, res) => {
  const { username, password } = req.body;
  // VULNERABLE: Hardcoded credentials
  if (username === 'admin' && password === 'admin123') {
    res.json({ success: true, role: 'admin' });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

// SAST Vulnerability 13: Missing Security Headers
app.get('/profile', (req, res) => {
  // VULNERABLE: No security headers set
  res.render('profile', { user: req.query.user });
});

// SAST Vulnerability 14: Insecure Cookie
app.post('/set-cookie', (req, res) => {
  // VULNERABLE: Cookie without httpOnly, secure, or sameSite flags
  res.cookie('session', req.body.session);
  res.json({ success: true });
});

// SAST Vulnerability 15: Information Disclosure
app.use((err, req, res, next) => {
  // VULNERABLE: Exposing stack trace in production
  res.status(500).json({
    error: err.message,
    stack: err.stack
  });
});

app.listen(PORT, () => {
  console.log(`Vulnerable app running on http://localhost:${PORT}`);
});

