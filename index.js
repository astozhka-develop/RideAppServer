require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bcrypt = require('bcryptjs'); // Кроссплатформенный модуль шифрования
const { Pool } = require('pg');

const app = express();
app.use(bodyParser.json());
app.use(cors());

const JWT_SECRET = process.env.JWT_SECRET || 'supersecretkey';

// Настройка пула подключений к Supabase
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Проверка работоспособности сервера (Health Check)
app.get('/api/health', (req, res) => {
  res.json({ ok: true });
});

// ==========================================
// 🔐 БЛОК АВТОРИЗАЦИИ И ПОЛЬЗОВАТЕЛЕЙ
// ==========================================

// 🚀 Регистрация нового пользователя (с защитой от дубликатов номеров)
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, phone, role, password } = req.body;
    if (!name || !phone || !password || !role) {
      return res.json({ ok: false, error: 'Заповніть всі обов\'язкові поля' });
    }
    
    // Проверка, существует ли уже пользователь с таким телефоном
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
    
    const user = result.rows[0];
    
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      return res.json({ ok: false, error: 'Невірний пароль' });
    }
    
    // Вшиваем ID и роль в JWT токен безопасности
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

// ==========================================
// 🗺️ БЛОК ПОЕЗДОК (АКТИВНЫЕ МАРШРУТЫ)
// ==========================================

// 🚀 Создать активный маршрут на карте (для Водителя или Пассажира)
app.post('/api/trips', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.json({ ok: false, error: 'Нет токена авторизации' });

    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    
    const { role, startLat, startLon, endLat, endLon, startAddress, endAddress } = req.body;

    // Сначала закрываем предыдущие незавершенные маршруты этого пользователя, если они были
    await pool.query(
      "UPDATE active_trips SET status = 'cancelled' WHERE user_id = $1 AND status = 'searching'",
      [decoded.id]
    );

    // Записываем новый маршрут в Supabase
    const result = await pool.query(
      `INSERT INTO active_trips (user_id, role, start_lat, start_lon, end_lat, end_lon, start_address, end_address) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`,
      [decoded.id, role, startLat, startLon, endLat, endLon, startAddress, endAddress]
    );

    res.json({ ok: true, tripId: result.rows[0].id });
  } catch (err) {
    console.error('Trip creation error:', err.message);
    res.json({ ok: false, error: 'Помилка сервера при створенні маршруту: ' + err.message });
  }
});

// 🚀 Получить список активных попутных ВОДИТЕЛЕЙ для карты Пассажира
app.get('/api/trips/drivers', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.json({ ok: false, error: 'Нет токена авторизации' });

    // Достаем всех водителей со статусом поиска пассажиров, подтягивая их профиль (номер, машину, рейтинг)
    const result = await pool.query(
      `SELECT t.id AS "tripId", t.user_id AS "driverId", t.start_lat AS "startLat", t.start_lon AS "startLon", 
              t.end_lat AS "endLat", t.end_lon AS "endLon", t.start_address AS "startAddress", t.end_address AS "endAddress",
              u.name, u.phone, u.car_make AS "carMake", u.plate_number AS "plateNumber"
       FROM active_trips t
       JOIN users u ON t.user_id = u.id
       WHERE t.role = 'driver' AND t.status = 'searching'`
    );

    res.json({ ok: true, drivers: result.rows });
  } catch (err) {
    console.error('Get drivers error:', err.message);
    res.json({ ok: false, error: 'Помилка сервера: ' + err.message });
  }
});

// ==========================================
// 💰 БЛОК СТАВОК (ТОРГИ И ПУШ-СИСТЕМА ДЛЯ MVP)
// ==========================================

// 🚀 Пассажир делает ставку выбранному водителю (с лимитом в 3 попытки!)
app.post('/api/bids', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.json({ ok: false, error: 'Нет токена авторизации' });

    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET);

    const { tripId, driverId, proposedPrice, passengerCount } = req.body;

    // 1. Проверяем, сколько раз этот пассажир уже предлагал цену этому водителю по данной поездке
    const checkAttempts = await pool.query(
      `SELECT COUNT(*) FROM ride_bids 
       WHERE trip_id = $1 AND passenger_id = $2 AND driver_id = $3`,
      [tripId, decoded.id, driverId]
    );

    const currentAttempts = parseInt(checkAttempts.rows[0].count);

    if (currentAttempts >= 3) {
      return res.json({ 
        ok: false, 
        error: 'Ви вичерпали ліміт ставок (макс. 3) для цього водія! Запропонуйте іншому.' 
      });
    }

    const nextAttemptNumber = currentAttempts + 1;

    // 2. Создаем запись о предложении
    await pool.query(
      `INSERT INTO ride_bids (trip_id, passenger_id, driver_id, proposed_price, passenger_count, attempt_number) 
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [tripId, decoded.id, driverId, proposedPrice, passengerCount, nextAttemptNumber]
    );

    res.json({ 
      ok: true, 
      message: `Ставку №${nextAttemptNumber} надіслано водієві!`,
      attemptNumber: nextAttemptNumber 
    });
  } catch (err) {
    console.error('Bid error:', err.message);
    res.json({ ok: false, error: 'Помилка надсилання ставки: ' + err.message });
  }
});

// 🚀 Водитель проверяет входящие предложения от пассажиров (Опрос бэкенда вместо Firebase для MVP)
app.get('/api/bids/incoming', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.json({ ok: false, error: 'Нет токена авторизации' });

    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET);

    // Достаем актуальные активные ставки, адреса назначения пассажира и его имя
    const result = await pool.query(
      `SELECT b.id AS "bidId", b.proposed_price AS "price", b.passenger_count AS "passengers", b.attempt_number AS "attempt",
              u.name AS "passengerName", t.end_address AS "endAddress"
       FROM ride_bids b
       JOIN users u ON b.passenger_id = u.id
       JOIN active_trips t ON b.trip_id = t.id
       WHERE b.driver_id = $1 AND b.status = 'pending'
       ORDER BY b.created_at DESC`,
      [decoded.id]
    );

    res.json({ ok: true, incomingBids: result.rows });
  } catch (err) {
    res.json({ ok: false, error: err.message });
  }
});

// 🚀 Водитель принимает или отклоняет ставку
app.post('/api/bids/decision', async (req, res) => {
  try {
