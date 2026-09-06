require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');

const app = express();
app.use(bodyParser.json());
app.use(cors());

// 🔑 Секрет для JWT
const JWT_SECRET = process.env.JWT_SECRET || 'supersecretkey';

// 🔌 Подключение к Supabase/Postgres
const pool = new Pool({
  connectionString: process.env.DATABASE_URL, // в Render/Supabase укажи DATABASE_URL
  ssl: { rejectUnauthorized: false }
});

// 🚀 Эндпоинт проверки здоровья
app.get('/api/health', (req, res) => {
  res.json({ ok: true });
});

// 🚀 Регистрация
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, phone, role, password } = req.body;

    if (!name || !phone || !password) {
      return res.status(400).json({ ok: false, error: 'Missing fields' });
    }

    // Хэшируем пароль
    const password_hash = await bcrypt.hash(password, 10);

    // Вставляем в таблицу users
    const result = await pool.query(
      'INSERT INTO users (name, phone, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING id',
      [name, phone, password_hash, role]
    );

    res.json({ ok: true, userId: result.rows[0].id });
  } catch (err) {
    console.error('Registration error:', err.message);
    res.status(500).json({ ok: false, error: 'Server error: ' + err.message });
  }
});

// 🚀 Авторизация
app.post('/api/auth/login', async (req, res) => {
  try {
    const { phone, password } = req.body;

    if (!phone || !password) {
      return res.status(400).json({ ok: false, error: 'Missing fields' });
    }

    // Ищем пользователя по телефону
    const result = await pool.query('SELECT * FROM users WHERE phone = $1', [phone]);
    if (result.rows.length === 0) {
      return res.status(400).json({ ok: false, error: 'User not found' });
    }

    const user = result.rows[0];

    // Проверяем пароль
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      return res.status(401).json({ ok: false, error: 'Invalid password' });
    }

    // Генерация JWT токена
    const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ ok: true, token });
  } catch (err) {
    console.error('Login error:', err.message);
    res.status(500).json({ ok: false, error: 'Server error: ' + err.message });
  }
});

// 🚀 Запуск сервера
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
