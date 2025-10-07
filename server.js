require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const nodemailer = require('nodemailer');
const fetch = require('node-fetch');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;

// ---------------- PostgreSQL Connection ----------------
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

pool.connect()
  .then(() => console.log('✅ Connected to PostgreSQL database'))
  .catch(err => console.error('❌ Database connection error:', err));

(async () => {
  // ---------------- Create Tables (if not exist) ----------------
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      user_id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('doctor','patient')),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS doctors (
      doctor_id SERIAL PRIMARY KEY,
      user_id INT NOT NULL REFERENCES users(user_id),
      specialization TEXT,
      availability TEXT,
      contact TEXT
    );

    CREATE TABLE IF NOT EXISTS appointments (
      appointment_id SERIAL PRIMARY KEY,
      patient_id INT NOT NULL REFERENCES users(user_id),
      doctor_id INT NOT NULL REFERENCES doctors(doctor_id),
      date_time TIMESTAMP NOT NULL,
      status TEXT DEFAULT 'scheduled',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS prescriptions (
      prescription_id SERIAL PRIMARY KEY,
      appointment_id INT NOT NULL REFERENCES appointments(appointment_id),
      file_path TEXT NOT NULL,
      uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

  // ---------------- Seed Demo Data ----------------
  const { rows } = await pool.query('SELECT COUNT(*) AS count FROM users');
  if (parseInt(rows[0].count) === 0) {
    const docPass = await bcrypt.hash('doctor123', 10);
    const patPass = await bcrypt.hash('patient123', 10);

    const doctor = await pool.query(
      'INSERT INTO users (name,email,password,role) VALUES ($1,$2,$3,$4) RETURNING user_id',
      ['Dr. Raj', 'doctor@example.com', docPass, 'doctor']
    );

    await pool.query(
      'INSERT INTO doctors (user_id,specialization,availability,contact) VALUES ($1,$2,$3,$4)',
      [doctor.rows[0].user_id, 'General Physician', 'Mon-Fri 10:00-16:00', '9876543210']
    );

    await pool.query(
      'INSERT INTO users (name,email,password,role) VALUES ($1,$2,$3,$4)',
      ['Demo Patient', 'patient@example.com', patPass, 'patient']
    );

    console.log('🌱 Seeded demo accounts');
    console.log('Doctor: doctor@example.com / doctor123');
    console.log('Patient: patient@example.com / patient123');
  }
})();

// ---------------- Middleware ----------------
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'keyboard_cat_default_secret',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 24 * 60 * 60 * 1000 }
}));

// ---------------- Static Directories ----------------
const PUBLIC_DIR = path.join(__dirname, 'public');
const UPLOADS_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR);
app.use('/uploads', express.static(UPLOADS_DIR));
app.use(express.static(PUBLIC_DIR));

// ---------------- Multer Setup ----------------
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename: (req, file, cb) => {
    const safe = file.originalname.replace(/[^a-zA-Z0-9.\-_() ]/g, '_');
    cb(null, Date.now() + '-' + safe);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype === 'application/pdf') cb(null, true);
    else cb(new Error('Only PDF files allowed'));
  }
});

// ---------------- Email Notifications (optional) ----------------
let transporter = null;
if (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS) {
  transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: process.env.SMTP_PORT ? Number(process.env.SMTP_PORT) : 587,
    secure: process.env.SMTP_SECURE === 'true',
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
  });
}
async function sendNotification({ to, subject, text }) {
  console.log('[Notify]', subject, '→', to);
  if (!transporter) return;
  try {
    await transporter.sendMail({
      from: process.env.SMTP_FROM || 'no-reply@example.com',
      to, subject, text
    });
    console.log('Email sent to', to);
  } catch (err) {
    console.error('Email error', err.message);
  }
}

// ---------------- Zoom Helper Functions ----------------
async function getZoomAccessToken() {
  const res = await fetch('https://zoom.us/oauth/token', {
    method: 'POST',
    headers: {
      'Authorization': 'Basic ' + Buffer.from(process.env.ZOOM_CLIENT_ID + ':' + process.env.ZOOM_CLIENT_SECRET).toString('base64'),
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: 'grant_type=account_credentials&account_id=' + process.env.ZOOM_ACCOUNT_ID
  });
  if (!res.ok) {
    const errorText = await res.text();
    console.error('Zoom OAuth error:', errorText);
    throw new Error('Zoom OAuth error: ' + errorText);
  }
  const data = await res.json();
  return data.access_token;
}

async function createZoomMeeting(doctorEmail, dateTime) {
  const token = await getZoomAccessToken();
  const startTime = new Date(dateTime).toISOString();
  const res = await fetch(`https://api.zoom.us/v2/users/${encodeURIComponent(doctorEmail)}/meetings`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      topic: 'Healthcare Appointment',
      type: 2,
      start_time: startTime,
      duration: 30,
      timezone: 'UTC',
      settings: { join_before_host: true }
    })
  });
  if (!res.ok) {
    const errorText = await res.text();
    console.error('Zoom API error:', errorText);
    throw new Error('Zoom API error: ' + errorText);
  }
  const data = await res.json();
  return data.join_url;
}

// ---------------- Auth Middleware ----------------
function requireLogin(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: 'Not authenticated' });
  next();
}
function requireRole(role) {
  return (req, res, next) => {
    if (!req.session.user) return res.status(401).json({ error: 'Not authenticated' });
    if (req.session.user.role !== role) return res.status(403).json({ error: 'Forbidden' });
    next();
  };
}

// ---------------- Example Route ----------------
app.get('/', (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'index.html')));

// ---------------- Start Server ----------------
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
