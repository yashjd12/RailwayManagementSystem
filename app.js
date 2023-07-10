require('dotenv').config(); // Load environment variables from .env file

const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mysql = require('mysql');

const app = express();
const port = process.env.PORT || 8080;
const SECRET_KEY = process.env.SECRET_KEY;
const ADMIN_API_KEY = process.env.ADMIN_API_KEY ;

// Database configuration
const db = mysql.createConnection({
  host: 'localhost',
  user: process.env.MYSQL_USER,
  password: process.env.MYSQL_PASSWORD,
  database: process.env.MYSQL_DATABASE
});

// Connect to the database
db.connect(err => {
  if (err) {
    console.error('Failed to connect to the database:', err);
    return;
  }
  console.log('Connected to the database');
});


// Middleware
app.use(bodyParser.json());


//Generate Token
function generateToken(userId) {
    const expiresIn = '20m'; 
    const token = jwt.sign({ user_id: userId }, SECRET_KEY, { expiresIn });
    return token;
}


// Middleware to authenticate the access token
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) {
        res.status(401).json({ status: 'Unauthorized', status_code: 401 });
        return;
      }
    
      jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) {
          res.status(403).json({ status: 'Forbidden', status_code: 403 });
          return;
        }
    
        req.user = user;
        next();
    });
}


// Middleware to authenticate the admin API key
function authenticateAdminAPIKey(req, res, next) {
    const apiKey = req.headers['x-api-key'];
    if (apiKey !== ADMIN_API_KEY) {
      res.status(401).json({ status: 'Unauthorized', status_code: 401 });
      return;
    }
    next();
}



// Routes
//Create a User
app.post('/api/signup', (req, res) => {
  const { username, password, email } = req.body;

  // Hash the password
  bcrypt.hash(password, 10, (err, hashedPassword) => {
    if (err) {
      console.error('Failed to hash password:', err);
      res.status(500).json({ status: 'Internal Server Error' });
      return;
    }

    // Insert the user into the database
    const query = 'INSERT INTO users (username, password, email) VALUES (?, ?, ?)';
    db.query(query, [username, hashedPassword, email], (err, result) => {
      if (err) {
        console.error('Failed to create user:', err);
        res.status(500).json({ status: 'Internal Server Error' });
        return;
      }
      res.json({ status: 'Account successfully created', status_code: 200, user_id: result.insertId });
    });
  });
});


//Login and Token Generation
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
  
    // Find the user in the database
    const query = 'SELECT * FROM users WHERE username = ?';
    db.query(query, [username], (err, results) => {
      if (err) {
        console.error('Failed to fetch user:', err);
        res.status(500).json({ status: 'Internal Server Error' });
        return;
      }
  
      if (results.length === 0) {
        res.status(401).json({ status: 'Incorrect username/password provided. Please retry', status_code: 401 });
        return;
      }
  
      const user = results[0];
  
      // Compare the provided password with the stored hashed password
      bcrypt.compare(password, user.password, (err, passwordMatch) => {
        if (err) {
          console.error('Failed to compare passwords:', err);
          res.status(500).json({ status: 'Internal Server Error' });
          return;
        }
  
        if (!passwordMatch) {
          res.status(401).json({ status: 'Incorrect username/password provided. Please retry', status_code: 401 });
          return;
        }
  
        // Generate and send the access token
        const token = generateToken(user.id);
        res.json({ status: 'Login successful', status_code: 200, user_id: user.id, access_token: token });
      });
    });
  });


// Add a New Train
app.post('/api/trains/create', authenticateToken, authenticateAdminAPIKey, (req, res) => {
    const { train_name, source, destination, seat_capacity, arrival_time_at_source, arrival_time_at_destination } = req.body;
  
    // Insert the train into the database
    const query = 'INSERT INTO trains (train_name, source, destination, seat_capacity, arrival_time_at_source, arrival_time_at_destination) VALUES (?, ?, ?, ?, ?, ?)';
    db.query(query, [train_name, source, destination, seat_capacity, arrival_time_at_source, arrival_time_at_destination], (err, result) => {
      if (err) {
        console.error('Failed to add train:', err);
        res.status(500).json({ message: 'Failed to add train', status_code: 500 });
        return;
      }
      res.json({ message: 'Train added successfully', train_id: result.insertId });
    });
});


// Get Seat Availability
app.get('/api/trains/availability', (req, res) => {
    const { source, destination } = req.query;
  
    // Fetch trains between the specified source and destination
    const query = 'SELECT id AS train_id, train_name, (seat_capacity - IFNULL((SELECT SUM(no_of_seats) FROM bookings WHERE bookings.train_id = trains.id), 0)) AS available_seats FROM trains WHERE source = ? AND destination = ?';
    db.query(query, [source, destination], (err, results) => {
      if (err) {
        console.error('Failed to fetch seat availability:', err);
        res.status(500).json({ message: 'Failed to fetch seat availability', status_code: 500 });
        return;
      }
      res.json(results);
    });
});



// Book a Seat
app.post('/api/trains/:train_id/book', authenticateToken, (req, res) => {
    const { user_id, no_of_seats } = req.body;
    const { train_id } = req.params;
  
    // Check if the requested number of seats are available
    const availabilityQuery = 'SELECT seat_capacity - IFNULL((SELECT SUM(no_of_seats) FROM bookings WHERE bookings.train_id = ?), 0) AS available_seats FROM trains WHERE id = ?';
    db.query(availabilityQuery, [train_id, train_id], (err, results) => {
      if (err) {
        console.error('Failed to check seat availability:', err);
        res.status(500).json({ message: 'Failed to check seat availability', status_code: 500 });
        return;
      }
  
      const availableSeats = results[0].available_seats;
  
      if (availableSeats < no_of_seats) {
        res.status(400).json({ message: 'Not enough seats available', status_code: 400 });
        return;
      }
  
      // Start a transaction to handle the booking
      db.beginTransaction(err => {
        if (err) {
          console.error('Failed to start transaction:', err);
          res.status(500).json({ message: 'Failed to start transaction', status_code: 500 });
          return;
        }
  
        // Insert the booking into the database
        const bookingQuery = 'INSERT INTO bookings (user_id, train_id, no_of_seats) VALUES (?, ?, ?)';
        db.query(bookingQuery, [user_id, train_id, no_of_seats], (err, result) => {
          if (err) {
            db.rollback(() => {
              console.error('Failed to book seat:', err);
              res.status(500).json({ message: 'Failed to book seat', status_code: 500 });
            });
            return;
          }
  
          const bookingId = result.insertId;
  
        // Update the seat numbers for the booking
        const seatNumbers = Array.from({ length: no_of_seats }, (_, i) => i + 1);
        const updateQuery = 'UPDATE bookings SET seat_numbers = ? WHERE id = ?';
        db.query(updateQuery, [seatNumbers[1], bookingId], (err) => {
        if (err) {
            db.rollback(() => {
            console.error('Failed to update seat numbers:', err);
            res.status(500).json({ message: 'Failed to book seat', status_code: 500 });
            });
            return;
        }

        // Commit the transaction
        db.commit(err => {
            if (err) {
            db.rollback(() => {
                console.error('Failed to commit transaction:', err);
                res.status(500).json({ message: 'Failed to book seat', status_code: 500 });
            });
            return;
            }

            res.json({ message: 'Seat booked successfully', booking_id: bookingId, seat_number: seatNumbers[1] });
        });
        });

        });
      });
    });
});



// Get Specific Booking Details
app.get('/api/bookings/:booking_id', authenticateToken, (req, res) => {
    const { booking_id } = req.params;
  
    // Fetch the booking details
    const query = 'SELECT bookings.id AS booking_id, trains.id AS train_id, train_name, user_id, no_of_seats, seat_numbers, arrival_time_at_source, arrival_time_at_destination FROM bookings INNER JOIN trains ON bookings.train_id = trains.id WHERE bookings.id = ?';
    db.query(query, [booking_id], (err, results) => {
      if (err) {
        console.error('Failed to fetch booking details:', err);
        res.status(500).json({ message: 'Failed to fetch booking details', status_code: 500 });
        return;
      }
  
      if (results.length === 0) {
        res.status(404).json({ message: 'Booking not found', status_code: 404 });
        return;
      }
  
      res.json(results[0]);
    });
});



// Start the server
app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});
