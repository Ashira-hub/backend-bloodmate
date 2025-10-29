require('dotenv').config();

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const path = require('path');

// Create Express app
const app = express();

// Configure CORS
const corsOptions = {
  origin: [
    'http://localhost:8081', // React Native debugger
    'http://localhost:19006', // Expo web
    'exp://*', // Expo app
    'https://bloodmate-*.d1m5y7g4x6y5n1.amplifyapp.com', // Your frontend domain if hosted
  ],
  methods: 'GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS',
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  optionsSuccessStatus: 204,
};

// Apply CORS middleware
app.use(cors(corsOptions));

// Handle preflight requests
app.options('*', cors(corsOptions));

const { Pool } = require('pg');

const PORT = process.env.PORT || 3001;

const poolConfig = {};

const DATABASE_URL = process.env.DATABASE_URL || process.env.RAILWAY_DATABASE_URL;

if (DATABASE_URL) {
  poolConfig.connectionString = DATABASE_URL;
  const sslEnabled =
    process.env.PGSSL === 'true' ||
    process.env.PGSSLMODE === 'require' ||
    process.env.PGSSLMODE === 'verify-full';
  if (sslEnabled) {
    poolConfig.ssl = { rejectUnauthorized: false };
  }
} else {
  poolConfig.host = process.env.PGHOST || process.env.PGHOSTADDR || 'localhost';
  poolConfig.port = Number(process.env.PGPORT || 5432);
  poolConfig.user = process.env.PGUSER || 'postgres';
  poolConfig.password = process.env.PGPASSWORD || '';
  poolConfig.database = process.env.PGDATABASE || 'bloodmate';

  if (!process.env.PGHOST) {
    console.warn('[BloodMate backend] No DATABASE_URL provided. Falling back to local PostgreSQL on localhost:5432.');
  }
}

const pool = new Pool(poolConfig);

// Body parsing middleware
app.use(express.json({ limit: '1mb' }));

// Log all requests
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`, {
    headers: req.headers,
    query: req.query,
    body: req.body
  });
  next();
});

async function ensureTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      full_name TEXT NOT NULL,
      mobile TEXT NOT NULL,
      dob TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      donor_status TEXT NOT NULL DEFAULT 'ready' CHECK (donor_status IN ('ready', 'need')),
      role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS addresses (
      id SERIAL PRIMARY KEY,
      user_id INTEGER UNIQUE NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      street TEXT NOT NULL,
      barangay TEXT NOT NULL,
      district TEXT NOT NULL,
      city TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS blood_profiles (
      id SERIAL PRIMARY KEY,
      user_id INTEGER UNIQUE NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      abo TEXT NOT NULL CHECK (abo IN ('A','B','O','AB')),
      rh TEXT NOT NULL CHECK (rh IN ('+','-')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`
    ALTER TABLE users
      ADD COLUMN IF NOT EXISTS donor_status TEXT;
  `);
  await pool.query(`
    ALTER TABLE users
      ALTER COLUMN donor_status SET DEFAULT 'ready';
  `);
  await pool.query(`
    UPDATE users SET donor_status = 'ready' WHERE donor_status IS NULL;
  `);

  await pool.query(`
    ALTER TABLE users
      ADD COLUMN IF NOT EXISTS role TEXT;
  `);
  await pool.query(`
    ALTER TABLE users
      ALTER COLUMN role SET DEFAULT 'user';
  `);
  await pool.query(`
    UPDATE users SET role = 'user' WHERE role IS NULL;
  `);
}

async function seedAdmin() {
  const adminEmail = (process.env.ADMIN_EMAIL || 'admin1@gmail.com').trim().toLowerCase();
  const adminPassword = process.env.ADMIN_PASSWORD || 'admin123';

  const existing = await pool.query('SELECT id, role FROM users WHERE email = $1 LIMIT 1', [adminEmail]);
  if (existing.rows.length > 0) {
    const row = existing.rows[0];
    if (row.role !== 'admin') {
      await pool.query('UPDATE users SET role = $1 WHERE id = $2', ['admin', row.id]);
    }
    return;
  }

  const hashed = await bcrypt.hash(adminPassword, 10);
  await pool.query(
    `INSERT INTO users (full_name, mobile, dob, email, password, donor_status, role)
     VALUES ($1, $2, $3, $4, $5, 'ready', 'admin')`,
    ['Administrator', '0000000000', '1970-01-01', adminEmail, hashed]
  );
}

app.get('/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'ok' });
  } catch (error) {
    res.status(500).json({ status: 'error', message: error.message });
  }
});

app.get('/api/seekers', async (_req, res) => {
  try {
    const result = await pool.query(
      `SELECT u.id,
              u.full_name,
              u.email,
              u.mobile,
              u.donor_status,
              a.street,
              a.barangay,
              a.district,
              a.city,
              b.abo,
              b.rh
       FROM users u
       LEFT JOIN addresses a ON a.user_id = u.id
       LEFT JOIN blood_profiles b ON b.user_id = u.id
       WHERE u.donor_status = 'need'
       ORDER BY u.created_at DESC
       LIMIT 10`
    );
    res.json(result.rows);
  } catch (error) {
    console.error('List seekers error:', error);
    res.status(500).json({ message: 'Failed to load seekers.' });
  }
});

app.get('/api/users/:id', async (req, res) => {
  const userId = Number(req.params.id);
  if (!userId || Number.isNaN(userId)) {
    return res.status(400).json({ message: 'Invalid user id.' });
  }
  try {
    const result = await pool.query(
      'SELECT id, full_name, mobile, dob, email, donor_status, role, created_at FROM users WHERE id = $1 LIMIT 1',
      [userId]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'User not found.' });
    }
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ message: 'Failed to fetch user.' });
  }
});

app.post('/api/auth/signup', async (req, res) => {
  const { fullName, mobile, dob, email, password } = req.body || {};

  if (!fullName || !mobile || !dob || !email || !password) {
    return res.status(400).json({ message: 'fullName, mobile, dob, email, and password are required.' });
  }

  try {
    const normalizedEmail = String(email).trim().toLowerCase();
    const existing = await pool.query('SELECT id FROM users WHERE email = $1 LIMIT 1', [normalizedEmail]);
    if (existing.rows.length > 0) {
      return res.status(409).json({ message: 'Email already registered.' });
    }

    const hashed = await bcrypt.hash(String(password), 10);
    const result = await pool.query(
      `INSERT INTO users (full_name, mobile, dob, email, password)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id` ,
      [String(fullName).trim(), String(mobile).trim(), String(dob).trim(), normalizedEmail, hashed]
    );

    res.status(201).json({ userId: result.rows[0].id });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ message: 'Failed to create account.' });
  }
});

app.post('/api/users/:id/address', async (req, res) => {
  const userId = Number(req.params.id);
  const { street, barangay, district, city } = req.body || {};

  if (!userId || Number.isNaN(userId)) {
    return res.status(400).json({ message: 'Invalid user id.' });
  }

  if (!street || !barangay || !district || !city) {
    return res.status(400).json({ message: 'street, barangay, district, and city are required.' });
  }

  try {
    const user = await pool.query('SELECT id FROM users WHERE id = $1 LIMIT 1', [userId]);
    if (user.rows.length === 0) {
      return res.status(404).json({ message: 'User not found.' });
    }

    await pool.query(
      `INSERT INTO addresses (user_id, street, barangay, district, city, updated_at)
       VALUES ($1, $2, $3, $4, $5, NOW())
       ON CONFLICT (user_id) DO UPDATE
         SET street = EXCLUDED.street,
             barangay = EXCLUDED.barangay,
             district = EXCLUDED.district,
             city = EXCLUDED.city,
             updated_at = NOW()` ,
      [userId, String(street).trim(), String(barangay).trim(), String(district).trim(), String(city).trim()]
    );

    res.json({ success: true });
  } catch (error) {
    console.error('Address save error:', error);
    res.status(500).json({ message: 'Failed to save address.' });
  }
});

app.get('/api/users/:id/address', async (req, res) => {
  const userId = Number(req.params.id);
  if (!userId || Number.isNaN(userId)) {
    return res.status(400).json({ message: 'Invalid user id.' });
  }
  try {
    const result = await pool.query(
      'SELECT user_id, street, barangay, district, city, created_at, updated_at FROM addresses WHERE user_id = $1 LIMIT 1',
      [userId]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Address not found.' });
    }
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Get address error:', error);
    res.status(500).json({ message: 'Failed to fetch address.' });
  }
});

app.post('/api/users/:id/blood', async (req, res) => {
  const userId = Number(req.params.id);
  const { abo, rh } = req.body || {};

  if (!userId || Number.isNaN(userId)) {
    return res.status(400).json({ message: 'Invalid user id.' });
  }

  if (!abo || !rh) {
    return res.status(400).json({ message: 'abo and rh are required.' });
  }

  try {
    const user = await pool.query('SELECT id FROM users WHERE id = $1 LIMIT 1', [userId]);
    if (user.rows.length === 0) {
      return res.status(404).json({ message: 'User not found.' });
    }

    await pool.query(
      `INSERT INTO blood_profiles (user_id, abo, rh, updated_at)
       VALUES ($1, $2, $3, NOW())
       ON CONFLICT (user_id) DO UPDATE
         SET abo = EXCLUDED.abo,
             rh = EXCLUDED.rh,
             updated_at = NOW()` ,
      [userId, String(abo).trim(), String(rh).trim()]
    );

    res.json({ success: true });
  } catch (error) {
    console.error('Blood profile save error:', error);
    res.status(500).json({ message: 'Failed to save blood profile.' });
  }
});

app.get('/api/users/:id/blood', async (req, res) => {
  const userId = Number(req.params.id);
  if (!userId || Number.isNaN(userId)) {
    return res.status(400).json({ message: 'Invalid user id.' });
  }
  try {
    const result = await pool.query(
      'SELECT user_id, abo, rh, created_at, updated_at FROM blood_profiles WHERE user_id = $1 LIMIT 1',
      [userId]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Blood profile not found.' });
    }
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Get blood error:', error);
    res.status(500).json({ message: 'Failed to fetch blood profile.' });
  }
});

app.patch('/api/users/:id/status', async (req, res) => {
  const userId = Number(req.params.id);
  const { donor_status } = req.body || {};
  if (!userId || Number.isNaN(userId)) {
    return res.status(400).json({ message: 'Invalid user id.' });
  }
  if (donor_status !== 'ready' && donor_status !== 'need') {
    return res.status(400).json({ message: "donor_status must be 'ready' or 'need'." });
  }
  try {
    const result = await pool.query('UPDATE users SET donor_status = $1 WHERE id = $2 RETURNING id', [donor_status, userId]);
    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'User not found.' });
    }
    res.json({ success: true });
  } catch (error) {
    console.error('Update donor status error:', error);
    res.status(500).json({ message: 'Failed to update donor status.' });
  }
});

app.post('/api/auth/signin', async (req, res) => {
  const { email, password } = req.body || {};

  if (!email || !password) {
    return res.status(400).json({ message: 'email and password are required.' });
  }

  try {
    const normalizedEmail = String(email).trim().toLowerCase();
    const result = await pool.query('SELECT id, password, role FROM users WHERE email = $1 LIMIT 1', [normalizedEmail]);

    if (result.rows.length === 0) {
      return res.status(401).json({ message: 'Invalid email or password.' });
    }

    const user = result.rows[0];
    const isMatch = await bcrypt.compare(String(password), user.password);

    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid email or password.' });
    }

    res.json({ userId: user.id, role: user.role });
  } catch (error) {
    console.error('Signin error:', error);
    res.status(500).json({ message: 'Failed to sign in.' });
  }
});

// Error handling middleware with CORS headers
app.use((err, req, res, next) => {
  // Set CORS headers for error responses
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
  res.header('Access-Control-Allow-Credentials', 'true');

  console.error('Error:', {
    message: err.message,
    stack: process.env.NODE_ENV === 'production' ? '🔒' : err.stack,
    path: req.path,
    method: req.method,
    body: req.body,
    params: req.params
  });

  // Handle CORS errors
  if (err.name === 'UnauthorizedError') {
    return res.status(401).json({ 
      success: false,
      message: 'Invalid or missing authentication token.'
    });
  }

  // Handle validation errors
  if (err.name === 'ValidationError') {
    return res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors: err.errors
    });
  }

  // Handle CORS preflight
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  // Handle other errors
  res.status(err.status || 500).json({
    success: false,
    message: process.env.NODE_ENV === 'production' 
      ? 'An unexpected error occurred.' 
      : err.message || 'Unexpected server error.'
  });
});

async function start() {
  try {
    await ensureTables();
    await seedAdmin();
    app.listen(PORT, () => {
      console.log(`Backend listening on port ${PORT}`);
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
}

start();
