// index.js
const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');

const app = express();
app.use(bodyParser.json());

// 🔑 Секрет для JWT (в реальном проекте вынеси в .env)
const JWT_SECRET = 'supersecretkey';

// 🚀 Эндпоинт проверки здоровья
app.get('/api/health', (req, res) => {
  res.json({ ok: true });
});

// 🚀 Регистрация (пока без базы, просто тестовый ответ)
app.post('/api/auth/register', (req, res) => {
  const { name, phone, password, role, telegram_id } = req.body;

  if (!name || !phone || !password) {
    return res.status(400).json({ ok: false, error: 'Missing fields' });
  }

  // В реальном проекте здесь будет сохранение в базу
  res.json({ ok: true, userId: 1, name, phone, role, telegram_id });
});

// 🚀 Авторизация (пока без базы, просто проверка пароля)
app.post('/api/auth/login', (req, res) => {
  const { phone, password } = req.body;

  if (!phone || !password) {
    return res.status(400).json({ ok: false, error: 'Missing fields' });
  }

  // В реальном проекте здесь будет проверка пользователя в базе
  if (password !== '123456') {
    return res.status(401).json({ ok: false, error: 'Invalid credentials' });
  }

  // Генерация JWT токена
  const token = jwt.sign({ phone }, JWT_SECRET, { expiresIn: '1h' });
  res.json({ ok: true, token });
});

// 🚀 Запуск сервера
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
