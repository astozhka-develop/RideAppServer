// index.js
const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bcrypt = require('bcrypt');

const app = express();
app.use(bodyParser.json());
app.use(cors());

// 🔑 Секрет для JWT (вынеси в .env на Render)
const JWT_SECRET = process.env.JWT_SECRET || 'supersecretkey';

// 🚀 Эндпоинт проверки здоровья
app.get('/api/health', (req, res) => {
  res.json({ ok: true });
});

// 🚀 Регистрация
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, phone, role, password, telegram_id } = req.body;

    if (!name || !phone) {
      return res.status(400).json({ ok: false, error: 'Missing fields' });
    }

    // Хэшируем пароль (если передан)
    let password_hash = null;
    if (password) {
      password_hash = await bcrypt.hash(password, 10);
    }

    // В реальном проекте: вставка в базу Supabase/Postgres
    // Пока возвращаем тестовый ответ
    res.json({
      ok: true,
      userId: 1,
      name,
      phone,
      role,
      telegram_id,
      password_hash
    });
  } catch (err) {
    console.error('Registration error:', err.message);
    console.log('Register request body:', req.body);
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

    // Для теста: пароль должен быть "123456"
    const valid = await bcrypt.compare(password, await bcrypt.hash("123456", 10));

    if (!valid) {
      return res.status(401).json({ ok: false, error: 'Invalid credentials' });
    }

    // Генерация JWT токена
    const token = jwt.sign({ phone }, JWT_SECRET, { expiresIn: '1h' });
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
