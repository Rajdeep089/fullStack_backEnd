const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const mysql = require('mysql2/promise');

const app = express();
const PORT = 3001;

app.use(bodyParser.json());

// MySQL database connection (replace with your own database credentials)
const pool = mysql.createPool({
  host: 'localhost',
  user: 'test123',
  password: 'test123',
  database: 'schemaX',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

// RESTful endpoint for user login
app.post('/api/login', async (req, res) => {
  const { usernameOrEmail, password } = req.body;

  try {
    // Check if the user exists(username or email)
    const [rows] = await pool.query('SELECT * FROM users WHERE username = ? OR email = ?', [usernameOrEmail, usernameOrEmail]);

    if (rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = rows[0];

    // Compare the provided password with the hashed password in the database(using bcrypt)
    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid password' });
    }

    // You may generate a JWT token here for authentication(using jsonwebtoken)

    res.status(200).json({ message: 'Login successful' });
  } catch (error) {
    console.error('Error during login:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// RESTful endpoint for user sign-up(username, email, password)
app.post('/api/signup', async (req, res) => {
  const { username, email, password } = req.body;

  try {
    // Check if the email is already in use(using MySQL)
    const [existingUser] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);

    if (existingUser.length > 0) {
      return res.status(400).json({ error: 'Email already in use' });
    }

    // Hash the password before storing it in the database(using bcrypt)
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert the new user into the database(using MySQL)
    await pool.query('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', [username, email, hashedPassword]);

    res.status(201).json({ message: 'Sign-up successful' });
  } catch (error) {
    console.error('Error during sign-up:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});
// Start the server(command: node server.js)
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${3001}`);
});