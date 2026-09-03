const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const app = express();

app.use(express.json());

// Подключение к Supabase PostgreSQL через переменную окружения
// В Render в Settings → Environment добавь DATABASE_URL со строкой подключения Supabase
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Регистрация
app.post('/auth/register', async (req, res) => {
  try {
    const { name, phone, password, role, telegram_id } = req.body;
    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (name, phone, password_hash, role, telegram_id) VALUES ($1,$2,$3,$4,$5) RETURNING id',
      [name, phone, hash, role, telegram_id]
    );
    res.json({ ok: true, userId: result.rows[0].id });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// Авторизация
app.post('/auth/login', async (req, res) => {
  try {
    const { phone, password } = req.body;
    const result = await pool.query('SELECT * FROM users WHERE phone=$1', [phone]);
    if (result.rows.length === 0) return res.status(400).json({ ok: false, error: 'User not found' });
    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(400).json({ ok: false, error: 'Wrong password' });
    res.json({ ok: true, userId: user.id, role: user.role });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// Список пользователей для админпанели
app.get('/admin/users', async (req, res) => {
  try {
    const result = await pool.query('SELECT id, name, phone, role, telegram_id FROM users');
    res.json({ ok: true, users: result.rows });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// Проверка здоровья
app.get('/api/health', (req, res) => {
  res.json({ ok: true });
});

app.listen(5000, '0.0.0.0', () => {
  console.log('Server running on port 5000');
});
