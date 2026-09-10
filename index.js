require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bcrypt = require('bcryptjs'); // 🔥 ИСПРАВЛЕНО: Кроссплатформенный модуль
const { Pool } = require('pg');

const app = express();
app.use(bodyParser.json());
app.use(cors());

const JWT_SECRET = process.env.JWT_SECRET || 'supersecretkey';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

app.get('/api/health', (req, res) => {
  res.json({ ok: true });
});

// 🚀 Регистрация нового пользователя
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, phone, role, password } = req.body;
    if (!name || !phone || !password || !role) {
      return res.json({ ok: false, error: 'Заповніть всі обов\'язкові поля' });
    }

    const checkUser = await pool.query('SELECT id FROM users WHERE phone = $1', [phone]);
    if (checkUser.rows.length > 0) {
      return res.json({ ok: false, error: 'Користувач з таким номером телефону вже зареєстрований!' });
    }

    const password_hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (name, phone, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING id',
      [name, phone, password_hash, role]
    );
    res.json({ ok: true, userId: result.rows[0].id });
  } catch (err) {
    console.error('Registration error:', err.message);
    res.json({ ok: false, error: 'Server error: ' + err.message });
  }
});

// 🚀 Авторизация (Логин)
app.post('/api/auth/login', async (req, res) => {
  try {
    const { phone, password } = req.body;
    if (!phone || !password) {
      return res.json({ ok: false, error: 'Missing fields' });
    }
    
    const result = await pool.query('SELECT * FROM users WHERE phone = $1', [phone]);
    if (result.rows.length === 0) {
      return res.json({ ok: false, error: 'Користувача не знайдено' });
    }
    
    // 🔥 ИСПРАВЛЕНО: Строго извлекаем первый элемент из массива rows
    const user = result.rows[0]; 
    
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      return res.json({ ok: false, error: 'Невірний пароль' });
    }
    
    const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ ok: true, token, role: user.role });
  } catch (err) {
    console.error('Login error:', err.message);
    res.json({ ok: false, error: 'Server error: ' + err.message });
  }
});

// 🚀 Получение данных профиля
app.get('/api/profile', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.json({ ok: false, error: 'Нет токена авторизации' });
    
    const token = authHeader.split(' ')[1]; 
    const decoded = jwt.verify(token, JWT_SECRET);

    const result = await pool.query(
      'SELECT id, name, phone, role, car_make AS "carMake", plate_number AS "plateNumber" FROM users WHERE id = $1',
      [decoded.id]
    );
    
    if (result.rows.length === 0) {
      return res.json({ ok: false, error: 'Користувача не знайдено' });
    }
    
    // 🔥 ИСПРАВЛЕНО: Возвращаем один чистый объект user
    res.json({ ok: true, user: result.rows[0] });
  } catch (err) {
    console.error('Profile GET error:', err.message);
    res.json({ ok: false, error: 'Помилка авторизації: ' + err.message });
  }
});

// 🚀 Обновление данных профиля водителя
app.put('/api/profile', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.json({ ok: false, error: 'Нет токена авторизации' });
    
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET);

    const { name, phone, carMake, plateNumber } = req.body;
    
    await pool.query(
      'UPDATE users SET name=$1, phone=$2, car_make=$3, plate_number=$4 WHERE id=$5',
      [name, phone, carMake, plateNumber, decoded.id]
    );
    
    res.json({ ok: true });
  } catch (err) {
    console.error('Profile PUT error:', err.message);
    res.json({ ok: false, error: 'Помилка сервера при оновленні даних' });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
