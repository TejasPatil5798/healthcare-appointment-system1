require('dotenv').config();
const express = require('express');
const session = require('express-session');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const nodemailer = require('nodemailer');
const fetch = require('node-fetch');

const app = express();
const PORT = process.env.PORT || 3000;

// -------------------- PostgreSQL Connection --------------------
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

pool.connect()
    .then(() => console.log('✅ Connected to PostgreSQL database'))
    .catch(err => console.error('❌ PostgreSQL connection error:', err.message));

// -------------------- Middleware --------------------
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: process.env.SESSION_SECRET || 'keyboard_cat_default_secret',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 24 * 60 * 60 * 1000 }
}));

// -------------------- Static Directories --------------------
const PUBLIC_DIR = path.join(__dirname, 'public');
const UPLOADS_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR);
app.use('/uploads', express.static(UPLOADS_DIR));
app.use(express.static(PUBLIC_DIR));

// -------------------- Multer --------------------
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

// -------------------- Email Setup --------------------
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

// -------------------- Zoom Helpers --------------------
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

// -------------------- Initialize Tables --------------------
(async () => {
    try {
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
            user_id INTEGER REFERENCES users(user_id) ON DELETE CASCADE,
            specialization TEXT,
            availability TEXT,
            contact TEXT
        );
        CREATE TABLE IF NOT EXISTS appointments (
            appointment_id SERIAL PRIMARY KEY,
            patient_id INTEGER REFERENCES users(user_id),
            doctor_id INTEGER REFERENCES doctors(doctor_id),
            date_time TIMESTAMP NOT NULL,
            status TEXT DEFAULT 'scheduled',
            zoom_link TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS prescriptions (
            prescription_id SERIAL PRIMARY KEY,
            appointment_id INTEGER REFERENCES appointments(appointment_id),
            file_path TEXT NOT NULL,
            uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );`);

        // Seed demo accounts if empty
        const { rows } = await pool.query('SELECT COUNT(*) FROM users');
        if (Number(rows[0].count) === 0) {
            const docPass = bcrypt.hashSync('doctor123', 10);
            const patPass = bcrypt.hashSync('patient123', 10);

            const doctor = await pool.query(
                `INSERT INTO users (name,email,password,role) VALUES ($1,$2,$3,$4) RETURNING user_id`,
                ['Dr. Raj', 'doctor@example.com', docPass, 'doctor']
            );
            await pool.query(
                `INSERT INTO doctors (user_id,specialization,availability,contact) VALUES ($1,$2,$3,$4)`,
                [doctor.rows[0].user_id, 'General Physician', 'Mon-Fri 10:00-16:00', '9876543210']
            );

            await pool.query(
                `INSERT INTO users (name,email,password,role) VALUES ($1,$2,$3,$4)`,
                ['Demo Patient', 'patient@example.com', patPass, 'patient']
            );

            console.log('✅ Seeded demo accounts');
        }
    } catch (err) {
        console.error('Error initializing tables:', err.message);
    }
})();

// -------------------- Auth Middleware --------------------
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

// -------------------- API Routes --------------------

// Session
app.get('/api/session', (req, res) => res.json({ user: req.session.user || null }));

// Register
app.post('/api/register', async (req, res) => {
    const { name, email, password, role, specialization, availability, contact } = req.body;
    if (!name || !email || !password || !role) return res.status(400).json({ error: 'Missing fields' });

    const hashed = bcrypt.hashSync(password, 10);
    try {
        const userResult = await pool.query(
            `INSERT INTO users (name,email,password,role) VALUES ($1,$2,$3,$4) RETURNING user_id`,
            [name, email, hashed, role]
        );
        if (role === 'doctor') {
            await pool.query(
                `INSERT INTO doctors (user_id,specialization,availability,contact) VALUES ($1,$2,$3,$4)`,
                [userResult.rows[0].user_id, specialization || 'General', availability || '', contact || '']
            );
        }
        res.json({ success: true, message: `${role} registered` });
    } catch (err) {
        if (err.message.includes('duplicate key')) return res.status(400).json({ error: 'Email already used' });
        console.error('Register error:', err);
        res.status(500).json({ error: 'DB error' });
    }
});

// Login
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Missing fields' });
    try {
        const result = await pool.query(`SELECT * FROM users WHERE email=$1`, [email]);
        const user = result.rows[0];
        if (!user || !bcrypt.compareSync(password, user.password))
            return res.status(400).json({ error: 'Invalid credentials' });

        let sessionUser = { user_id: user.user_id, name: user.name, email: user.email, role: user.role };
        if (user.role === 'doctor') {
            const dr = await pool.query(`SELECT doctor_id FROM doctors WHERE user_id=$1`, [user.user_id]);
            sessionUser.doctor_id = dr.rows[0]?.doctor_id || null;
        }
        req.session.user = sessionUser;
        res.json({ success: true, user: sessionUser });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'DB error' });
    }
});

// Logout
app.post('/api/logout', (req, res) => req.session.destroy(() => res.json({ success: true })));

// Get all doctors
app.get('/api/doctors', async (req, res) => {
    try {
        const { rows } = await pool.query(`
        SELECT d.doctor_id,d.specialization,d.availability,d.contact,u.name,u.email
        FROM doctors d JOIN users u ON d.user_id = u.user_id
        `);
        res.json({ doctors: rows });
    } catch (err) {
        console.error('Doctors fetch error:', err);
        res.status(500).json({ error: 'DB error' });
    }
});

// -------------------- Book Appointment --------------------
app.post('/api/book-appointment', requireLogin, requireRole('patient'), async (req, res) => {
    const { doctor_id, date_time, with_zoom } = req.body;
    if (!doctor_id || !date_time) return res.status(400).json({ error: 'Missing fields' });

    try {
        let zoom_link = null;
        if (with_zoom) {
            const dr = await pool.query(
                `SELECT u.email as doctor_email FROM doctors d JOIN users u ON d.user_id = u.user_id WHERE d.doctor_id=$1`,
                [doctor_id]
            );
            if (dr.rows[0]?.doctor_email)
                zoom_link = await createZoomMeeting(dr.rows[0].doctor_email, date_time);
        }

        // Use proper timestamp
        const dateISO = new Date(date_time).toISOString();

        const insert = await pool.query(
            `INSERT INTO appointments (patient_id,doctor_id,date_time,status,zoom_link)
             VALUES ($1,$2,$3,'scheduled',$4) RETURNING appointment_id`,
            [req.session.user.user_id, doctor_id, dateISO, zoom_link]
        );

        const drMail = await pool.query(
            `SELECT u.email as doctor_email FROM doctors d JOIN users u ON d.user_id = u.user_id WHERE d.doctor_id=$1`,
            [doctor_id]
        );
        if (drMail.rows[0])
            sendNotification({ to: drMail.rows[0].doctor_email, subject: 'New appointment', text: `Appointment ID ${insert.rows[0].appointment_id} booked.` });

        res.json({ success: true, appointment_id: insert.rows[0].appointment_id, zoom_link });
    } catch (err) {
        console.error('Book appointment error:', err);
        res.status(500).json({ error: err.message });
    }
});

// -------------------- Patient Appointments --------------------
app.get('/api/patient/appointments', requireLogin, requireRole('patient'), async (req, res) => {
    try {
        const { rows } = await pool.query(`
        SELECT a.appointment_id,a.date_time,a.status,u.name as doctor_name,d.specialization,p.file_path,a.zoom_link
        FROM appointments a
        JOIN doctors d ON a.doctor_id = d.doctor_id
        JOIN users u ON d.user_id = u.user_id
        LEFT JOIN prescriptions p ON a.appointment_id = p.appointment_id
        WHERE a.patient_id = $1
        ORDER BY a.date_time DESC
        `, [req.session.user.user_id]);
        res.json({ appointments: rows });
    } catch (err) {
        console.error('Patient appointments error:', err);
        res.status(500).json({ error: 'DB error' });
    }
});

// -------------------- Doctor Appointments --------------------
app.get('/api/doctor/appointments', requireLogin, requireRole('doctor'), async (req, res) => {
    try {
        const { rows } = await pool.query(`
        SELECT a.appointment_id,a.date_time,a.status,u.name as patient_name,u.email as patient_email,p.file_path,a.zoom_link
        FROM appointments a
        JOIN users u ON a.patient_id = u.user_id
        LEFT JOIN prescriptions p ON a.appointment_id = p.appointment_id
        WHERE a.doctor_id = $1
        ORDER BY a.date_time DESC
        `, [req.session.user.doctor_id]);
        res.json({ appointments: rows });
    } catch (err) {
        console.error('Doctor appointments error:', err);
        res.status(500).json({ error: 'DB error' });
    }
});

// -------------------- Upload Prescription --------------------
app.post('/api/doctor/upload-prescription', requireLogin, requireRole('doctor'), upload.single('prescription'), async (req, res) => {
    const { appointment_id } = req.body;
    if (!appointment_id) return res.status(400).json({ error: 'Missing appointment_id' });
    if (!req.file) return res.status(400).json({ error: 'Missing file' });

    const fp = `/uploads/${req.file.filename}`;
    try {
        await pool.query(`INSERT INTO prescriptions (appointment_id,file_path) VALUES ($1,$2)`, [appointment_id, fp]);
        await pool.query(`UPDATE appointments SET status='completed' WHERE appointment_id=$1`, [appointment_id]);

        const pat = await pool.query(`
        SELECT u.email as patient_email FROM appointments a JOIN users u ON a.patient_id = u.user_id WHERE a.appointment_id=$1
        `, [appointment_id]);
        if (pat.rows[0])
            sendNotification({ to: pat.rows[0].patient_email, subject: 'Prescription uploaded', text: `Prescription for appointment ${appointment_id} is ready.` });

        res.json({ success: true, file: fp });
    } catch (err) {
        console.error('Upload prescription error:', err);
        res.status(500).json({ error: 'DB error' });
    }
});

// -------------------- Get Prescription --------------------
app.get('/api/prescription/:appointment_id', requireLogin, async (req, res) => {
    try {
        const { rows } = await pool.query(`
        SELECT * FROM prescriptions WHERE appointment_id=$1 ORDER BY uploaded_at DESC LIMIT 1
        `, [req.params.appointment_id]);
        if (rows.length === 0) return res.status(404).json({ error: 'No prescription found' });
        res.json({ prescription: rows[0] });
    } catch (err) {
        console.error('Get prescription error:', err);
        res.status(500).json({ error: 'DB error' });
    }
});

// -------------------- Frontend --------------------
app.get('/', (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'index.html')));

// -------------------- Start Server --------------------
app.listen(PORT, () => console.log(`🚀 Server running at http://localhost:${PORT}`));
