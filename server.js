// server.js
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 3000;

const fetch = require('node-fetch');
const jwt = require('jsonwebtoken');

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: process.env.SESSION_SECRET || 'keyboard_cat_default_secret',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 24 * 60 * 60 * 1000 }
}));

// Static directories
const PUBLIC_DIR = path.join(__dirname, 'public');
const UPLOADS_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR);

app.use('/uploads', express.static(UPLOADS_DIR));
app.use(express.static(PUBLIC_DIR));

// Multer (PDF uploads only)
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

// Email notifications (optional)
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


// Helper: Get Zoom access token
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

// Helper: Create Zoom meeting
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

// SQLite DB
const DB_FILE = path.join(__dirname, 'database.sqlite');

// SAFETY: delete corrupt DB if needed
if (fs.existsSync(DB_FILE)) {
    try {
        new sqlite3.Database(DB_FILE).close();
    } catch (err) {
        console.error('Corrupt DB detected, deleting...');
        fs.unlinkSync(DB_FILE);
    }
}

const db = new sqlite3.Database(DB_FILE, (err) => {
    if (err) console.error('DB open error', err);
    else console.log('SQLite DB opened at', DB_FILE);
});

// Schema
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('doctor','patient')),
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  )`);

    db.run(`CREATE TABLE IF NOT EXISTS doctors (
    doctor_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    specialization TEXT,
    availability TEXT,
    contact TEXT,
    FOREIGN KEY(user_id) REFERENCES users(user_id)
  )`);

    db.run(`CREATE TABLE IF NOT EXISTS appointments (
    appointment_id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id INTEGER NOT NULL,
    doctor_id INTEGER NOT NULL,
    date_time TEXT NOT NULL,
    status TEXT DEFAULT 'scheduled',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(patient_id) REFERENCES users(user_id),
    FOREIGN KEY(doctor_id) REFERENCES doctors(doctor_id)
  )`);

    db.run(`CREATE TABLE IF NOT EXISTS prescriptions (
    prescription_id INTEGER PRIMARY KEY AUTOINCREMENT,
    appointment_id INTEGER NOT NULL,
    file_path TEXT NOT NULL,
    uploaded_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(appointment_id) REFERENCES appointments(appointment_id)
  )`);

    // Seed accounts
    db.get("SELECT COUNT(*) AS c FROM users", (err, row) => {
        if (!err && row && row.c === 0) {
            const docPass = bcrypt.hashSync('doctor123', 10);
            const patPass = bcrypt.hashSync('patient123', 10);

            db.run(`INSERT INTO users (name,email,password,role) VALUES (?,?,?,?)`,
                ['Dr. Raj', 'doctor@example.com', docPass, 'doctor'],
                function (err) {
                    if (!err) {
                        const uid = this.lastID;
                        db.run(`INSERT INTO doctors (user_id,specialization,availability,contact) VALUES (?,?,?,?)`,
                            [uid, 'General Physician', 'Mon-Fri 10:00-16:00', '9876543210']);
                    }
                });

            db.run(`INSERT INTO users (name,email,password,role) VALUES (?,?,?,?)`,
                ['Demo Patient', 'patient@example.com', patPass, 'patient']);

            console.log('Seeded demo accounts ✅');
            console.log('Doctor: doctor@example.com / doctor123');
            console.log('Patient: patient@example.com / patient123');
        }
    });
});

// Middleware guards
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

// API Routes
app.get('/api/session', (req, res) => res.json({ user: req.session.user || null }));

app.post('/api/register', (req, res) => {
    const { name, email, password, role, specialization, availability, contact } = req.body;
    if (!name || !email || !password || !role) return res.status(400).json({ error: 'Missing fields' });

    const hashed = bcrypt.hashSync(password, 10);
    db.run(`INSERT INTO users (name,email,password,role) VALUES (?,?,?,?)`,
        [name, email, hashed, role], function (err) {
            if (err) {
                if (err.message && err.message.includes('UNIQUE')) return res.status(400).json({ error: 'Email already used' });
                return res.status(500).json({ error: 'DB error' });
            }
            const newUserId = this.lastID;
            if (role === 'doctor') {
                db.run(`INSERT INTO doctors (user_id,specialization,availability,contact) VALUES (?,?,?,?)`,
                    [newUserId, specialization || 'General', availability || '', contact || '']);
            }
            res.json({ success: true, message: `${role} registered` });
        });
});

app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Missing fields' });

    db.get(`SELECT * FROM users WHERE email = ?`, [email], (err, user) => {
        if (err) return res.status(500).json({ error: 'DB error' });
        if (!user) return res.status(400).json({ error: 'Invalid credentials' });
        if (!bcrypt.compareSync(password, user.password)) return res.status(400).json({ error: 'Invalid credentials' });

        if (user.role === 'doctor') {
            db.get(`SELECT doctor_id FROM doctors WHERE user_id = ?`, [user.user_id], (err2, dr) => {
                req.session.user = { user_id: user.user_id, name: user.name, email: user.email, role: user.role, doctor_id: dr ? dr.doctor_id : null };
                res.json({ success: true, user: req.session.user });
            });
        } else {
            req.session.user = { user_id: user.user_id, name: user.name, email: user.email, role: user.role };
            res.json({ success: true, user: req.session.user });
        }
    });
});

app.post('/api/logout', (req, res) => {
    req.session.destroy(() => res.json({ success: true }));
});

app.get('/api/doctors', (req, res) => {
    db.all(`SELECT d.doctor_id,d.specialization,d.availability,d.contact,u.name,u.email
          FROM doctors d JOIN users u ON d.user_id = u.user_id`, (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB error' });
        res.json({ doctors: rows });
    });
});

app.post('/api/book-appointment', requireLogin, requireRole('patient'), async (req, res) => {
    const { doctor_id, date_time, with_zoom } = req.body;
    if (!doctor_id || !date_time) return res.status(400).json({ error: 'Missing fields' });

    let zoom_link = null;
    try {
        if (with_zoom) {
            // Get doctor email
            const dr = await new Promise((resolve, reject) => {
                db.get(`SELECT u.email as doctor_email FROM doctors d JOIN users u ON d.user_id = u.user_id WHERE d.doctor_id = ?`, [doctor_id], (err, row) => {
                    if (err) reject(err);
                    else resolve(row);
                });
            });
            if (dr && dr.doctor_email) {
                zoom_link = await createZoomMeeting(dr.doctor_email, date_time);
            }
        }
    } catch (e) {
        return res.status(500).json({ error: 'Zoom meeting creation failed' });
    }

    db.run(
        `INSERT INTO appointments (patient_id,doctor_id,date_time,status,zoom_link) VALUES (?,?,?,?,?)`,
        [req.session.user.user_id, doctor_id, date_time, 'scheduled', zoom_link],
        function (err) {
            if (err) return res.status(500).json({ error: 'DB error' });
            const apptId = this.lastID;

            db.get(
                `SELECT u.email as doctor_email FROM doctors d JOIN users u ON d.user_id = u.user_id WHERE d.doctor_id = ?`,
                [doctor_id],
                (err2, dr) => {
                    if (dr && dr.doctor_email)
                        sendNotification({
                            to: dr.doctor_email,
                            subject: 'New appointment',
                            text: `Appointment ID ${apptId} booked.`,
                        });
                }
            );
            res.json({ success: true, appointment_id: apptId, zoom_link });
        }
    );
});

app.get('/api/patient/appointments', requireLogin, requireRole('patient'), (req, res) => {
    const sql = `SELECT a.appointment_id,a.date_time,a.status,u.name as doctor_name,d.specialization,p.file_path,a.zoom_link
               FROM appointments a
               JOIN doctors d ON a.doctor_id = d.doctor_id
               JOIN users u ON d.user_id = u.user_id
               LEFT JOIN prescriptions p ON a.appointment_id = p.appointment_id
               WHERE a.patient_id = ?
               ORDER BY a.date_time DESC`;
    db.all(sql, [req.session.user.user_id], (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB error' });
        res.json({ appointments: rows });
    });
});

app.get('/api/doctor/appointments', requireLogin, requireRole('doctor'), (req, res) => {
    const drId = req.session.user.doctor_id;
    const sql = `SELECT a.appointment_id,a.date_time,a.status,u.name as patient_name,u.email as patient_email,p.file_path,a.zoom_link
               FROM appointments a
               JOIN users u ON a.patient_id = u.user_id
               LEFT JOIN prescriptions p ON a.appointment_id = p.appointment_id
               WHERE a.doctor_id = ?
               ORDER BY a.date_time DESC`;
    db.all(sql, [drId], (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB error' });
        res.json({ appointments: rows });
    });
});

app.post('/api/doctor/upload-prescription', requireLogin, requireRole('doctor'), upload.single('prescription'), (req, res) => {
    const { appointment_id } = req.body;
    if (!appointment_id) return res.status(400).json({ error: 'Missing appointment_id' });
    if (!req.file) return res.status(400).json({ error: 'Missing file' });

    const fp = `/uploads/${req.file.filename}`;
    db.run(`INSERT INTO prescriptions (appointment_id,file_path) VALUES (?,?)`, [appointment_id, fp], function (err) {
        if (err) return res.status(500).json({ error: 'DB error' });
        db.run(`UPDATE appointments SET status = 'completed' WHERE appointment_id = ?`, [appointment_id]);

        db.get(`SELECT u.email as patient_email FROM appointments a JOIN users u ON a.patient_id = u.user_id WHERE a.appointment_id = ?`,
            [appointment_id], (err2, row) => {
                if (row && row.patient_email) sendNotification({ to: row.patient_email, subject: 'Prescription uploaded', text: `Prescription for appointment ${appointment_id} is ready.` });
            });
        res.json({ success: true, file: fp });
    });
});

app.get('/api/prescription/:appointment_id', requireLogin, (req, res) => {
    db.get(`SELECT * FROM prescriptions WHERE appointment_id = ? ORDER BY uploaded_at DESC LIMIT 1`,
        [req.params.appointment_id], (err, row) => {
            if (err) return res.status(500).json({ error: 'DB error' });
            if (!row) return res.status(404).json({ error: 'No prescription found' });
            res.json({ prescription: row });
        });
});

// Serve frontend
app.get('/', (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'index.html')));

// Start server
app.listen(PORT, () => console.log(`🚀 Server running at http://localhost:${PORT}`));
