const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const app = express();
const PORT = 5000;
const path = require('path'); // To serve static HTML 



// Connect to MongoDB database
mongoose.connect(process.env.MONGO_URL)
.then(() => console.log('Connected to MongoDB'))
.catch((error) => console.error('Error connecting to MongoDB:', error));

// Defining a Schema for User Data collection
const userSchema = new mongoose.Schema({
  username: {type: String, required: true},
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true}, 
  savedPasswords: [String],
});

// Creating a User model based

const User = mongoose.model('User', userSchema);

// Middleware to parse JSON bodies
app.use(express.json());

// Middleware for JWT validation
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) {
    return res.status(401).json({ error: 'Unauthorized' })
  }

  jwt.verify(token, 'secret', (err, decoded) => {
    if (err) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    req.user = decoded;
    next();
  });
};

// Route to register a new user
app.post('/api/register', async (req, res) => {
  res.sendFile(__dirname + '/public/api/register.html');
  try {
    // Check if email already exist
    const existingUser = await User.findOne({ email: req.body.email });
    if (existingUser) {
      return res.status(400).json({ error: 'Email already exist' });
    }

    // Hashing the password
    const hashedPassword = await bcrypt.hash(req.body.password, 10);

    // Create New User
    const newUser = new User({
      username: req.body.username,
      email: req.body.email,
      password: hashedPassword
    });
    await newUser.save();

    return res.status(201).json({ message: 'User registeration successful'});
  } catch (error) {
    console.log(error)
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Login Route for user 
app.post('/api/login', async (req, res) => {
  res.sendFile(__dirname + '/public/api/login.html');

  try {
    // Check if email exists
    const user = await User.findOne({ email: req.body.email });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // compare password with hashed password
    const isMatch = await bcrypt.compare(req.body.password, user.password);
    if (isMatch) {
      return res.status(401).json({ error: 'Invalid password' });
    }

    // Generate JWT token 
    const token = jwt.sign({ id: user._id, email: user.email }, 'secret', { expiresIn: '1h'});
    return res.status(200).json({ token });
  } catch (error) {
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Protected route to get user details
app.get('/api/user', verifyToken, async (req, res) => {
  try {
    // Fetch user details with decoded token
    const user = await User.findById(req.user.id);
    if(!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.status(200).json({ username: user.username, email: user.email });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Route to save generated password to the savedPassword array (Protected)
app.post('/api/user/save-password', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if(!user) {
      return res.status(404).json({ error: 'User not found'});
    }

    // Add new generated password to the savedPasswords array
    user.savedPasswords.push(req.body.password);
    await user.save();

    res.status(200).json({ message: 'Password saved successfully'});

  } catch(error) {
    res.status(500).json({error: 'Internal Server error'});
  }
})

app.use(express.static(path.join(__dirname, 'public')));

app.use(express.json());


// Default route
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Server is running on ${PORT}`)
});

// Save picked Passwords generated

