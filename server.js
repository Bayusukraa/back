// backend/server.js
// Backend sederhana: Node.js + Express + PostgreSQL
// Install: npm install express pg bcrypt jsonwebtoken multer cors dotenv

const express    = require('express');
const { Pool }   = require('pg');
const bcrypt     = require('bcrypt');
const jwt        = require('jsonwebtoken');
const multer     = require('multer');
const cors       = require('cors');
const path       = require('path');
const fs         = require('fs');
require('dotenv').config();

const app  = express();
const PORT = process.env.PORT || 3000;

// ── CORS + JSON ───────────────────────────────────────────────────────────────
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static('uploads'));

// ── POSTGRESQL ────────────────────────────────────────────────────────────────
const pool = new Pool({
  host:     process.env.PG_HOST     || 'localhost',
  port:     process.env.PG_PORT     || 5432,
  database: process.env.PG_DB       || 'accidentguard',
  user:     process.env.PG_USER     || 'postgres',
  password: process.env.PG_PASSWORD || 'password',
});

// ── INIT DB ───────────────────────────────────────────────────────────────────
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id                SERIAL PRIMARY KEY,
      username          VARCHAR(50) UNIQUE NOT NULL,
      email             VARCHAR(100) UNIQUE NOT NULL,
      password_hash     TEXT NOT NULL,
      full_name         VARCHAR(100),
      phone             VARCHAR(20),
      telegram_id       VARCHAR(50),
      photo_url         TEXT,
      emergency_contact TEXT,
      created_at        TIMESTAMP DEFAULT NOW()
    );
  `);
  console.log('✅ DB siap');
}
initDB().catch(console.error);

// ── JWT HELPER ────────────────────────────────────────────────────────────────
const JWT_SECRET = process.env.JWT_SECRET || 'accidentguard_secret_change_this';

function signToken(userId) {
  return jwt.sign({ userId }, JWT_SECRET, { expiresIn: '30d' });
}

function authMiddleware(req, res, next) {
  const header = req.headers.authorization || '';
  const token  = header.replace('Bearer ', '');
  if (!token) return res.status(401).json({ message: 'Token tidak ada' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ message: 'Token tidak valid' });
  }
}

// ── MULTER (photo upload) ─────────────────────────────────────────────────────
if (!fs.existsSync('uploads')) fs.mkdirSync('uploads');

const storage = multer.diskStorage({
  destination: 'uploads/',
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, `user_${req.user.userId}_${Date.now()}${ext}`);
  },
});
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
  fileFilter: (_, file, cb) => {
    if (file.mimetype.startsWith('image/')) cb(null, true);
    else cb(new Error('Hanya file gambar'));
  },
});

// ── ROUTES ────────────────────────────────────────────────────────────────────

// POST /api/auth/register
app.post('/api/auth/register', async (req, res) => {
  const { username, email, password, full_name } = req.body;
  if (!username || !email || !password)
    return res.status(400).json({ message: 'Field wajib tidak lengkap' });

  try {
    const exists = await pool.query(
      'SELECT id FROM users WHERE email=$1 OR username=$2', [email, username]);
    if (exists.rows.length)
      return res.status(409).json({ message: 'Email atau username sudah digunakan' });

    const hash = await bcrypt.hash(password, 10);
    await pool.query(
      'INSERT INTO users (username, email, password_hash, full_name) VALUES ($1,$2,$3,$4)',
      [username, email, hash, full_name || '']);
    res.status(201).json({ message: 'Registrasi berhasil' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: 'Server error' });
  }
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
    const user   = result.rows[0];
    if (!user) return res.status(401).json({ message: 'Email tidak ditemukan' });

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok)  return res.status(401).json({ message: 'Password salah' });

    const token = signToken(user.id);
    delete user.password_hash;
    res.json({ token, user });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: 'Server error' });
  }
});

// GET /api/profile
app.get('/api/profile', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id,username,email,full_name,phone,telegram_id,photo_url,emergency_contact,created_at FROM users WHERE id=$1',
      [req.user.userId]);
    if (!result.rows.length) return res.status(404).json({ message: 'User tidak ditemukan' });
    res.json({ user: result.rows[0] });
  } catch (e) {
    res.status(500).json({ message: 'Server error' });
  }
});

// PUT /api/profile
app.put('/api/profile', authMiddleware, async (req, res) => {
  const { full_name, phone, telegram_id, emergency_contact } = req.body;
  try {
    const result = await pool.query(
      `UPDATE users SET full_name=$1, phone=$2, telegram_id=$3, emergency_contact=$4
       WHERE id=$5
       RETURNING id,username,email,full_name,phone,telegram_id,photo_url,emergency_contact`,
      [full_name, phone, telegram_id, emergency_contact, req.user.userId]);
    res.json({ user: result.rows[0] });
  } catch (e) {
    res.status(500).json({ message: 'Server error' });
  }
});

// POST /api/profile/photo
app.post('/api/profile/photo', authMiddleware, upload.single('photo'), async (req, res) => {
  if (!req.file) return res.status(400).json({ message: 'File tidak ada' });
  const photoUrl = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;
  try {
    await pool.query('UPDATE users SET photo_url=$1 WHERE id=$2', [photoUrl, req.user.userId]);
    res.json({ photo_url: photoUrl });
  } catch (e) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.listen(PORT, () => console.log(`🚀 Server jalan di port ${PORT}`));
