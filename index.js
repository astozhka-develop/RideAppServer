// index.js
const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bcrypt = require('bcrypt');
const { Pool } = require('pg'); // Подключаем драйвер базы данных Postgres

const app = express();
app.use(bodyParser.json());
app.use(cors());

// 🔑 Секрет для JWT
const JWT_SECRET = process.env.JWT_SECRET || 'supersecretkey';

// 🛢️ Настройка подключения к базе данных Supabase
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false // Обязательно для безопасного подключения к Supabase в облаке
  }
});

// Проверка подключения к базе при старте
pool.connect((err, client, release) => {
  if (err) {
    return console.error('Ошибка подключения к Supabase:', err.stack);
  }
  console.log('Успешно подключено к базе данных Supabase! 🎉');
  release();
});

// 🚀 Эндпоинт проверки здоровья
app.get('/api/health', (req, res) => {
  res.json({ ok: true });
});

// 🚀 Регистрация пользователя в РЕАЛЬНУЮ базу данных
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

    // Делаем реальный SQL-запрос в таблицу users в Supabase
    // id сгенерируется базой автоматически, а мы его заберем через RETURNING id
    const query = `
      INSERT INTO users (name, phone, role, password_hash, telegram_id)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING id;
    `;
    const values = [name, phone, role || 'user', password_hash, telegram_id || null];

    const result = await pool.query(query, values);
    const newUserId = result.rows[0].id; // Получаем реальный ID из базы данных

    console.log(`Пользователь успешно зарегистрирован в базе Supabase с ID: ${newUserId}`);

    // Возвращаем точный ответ приложению Android
    res.json({
      ok: true,
      userId: newUserId,
      name,
      phone,
      role
    });

  } catch (err) {
    console.error('Registration error:', err.message);
    console.log('Register request body:', req.body);
    res.status(500).json({ ok: false, error: 'Server error: ' + err.message });
  }
});

// 🚀 Авторизация (Логин) через реальную базу
app.post('/api/auth/login', async (req, res) => {
  try {
    const { phone, password } = req.body;
    if (!phone || !password) {
      return res.status(400).json({ ok: false, error: 'Missing fields' });
    }

    // Ищем пользователя в базе по номеру телефона
    const userResult = await pool.query('SELECT * FROM users WHERE phone = $1', [phone]);
    
    if (userResult.rows.length === 0) {
      return res.status(401).json({ ok: false, error: 'Пользователь не найден' });
    }

    const user = userResult.rows[0];

    // Проверяем, совпадает ли пароль
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) {
      return res.status(401).json({ ok: false, error: 'Неверный пароль' });
    }

    // Генерация JWT токена
    const token = jwt.sign({ id: user.id, phone: user.phone }, JWT_SECRET, { expiresIn: '1h' });
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