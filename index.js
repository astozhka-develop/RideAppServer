require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bcrypt = require('bcryptjs'); 
const { Pool } = require('pg');

const app = express();
app.use(bodyParser.json());
app.use(cors());

const JWT_SECRET = process.env.JWT_SECRET || 'supersecretkey';
const PORT = process.env.PORT || 5000;

// Настройка пула подключений к Supabase (PostgreSQL)
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

// 🚀 Регистрация нового пользователя
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, phone, role, password, carMake, plateNumber, carPhotoUrl } = req.body;
    if (!name || !phone || !password || !role) {
      return res.json({ ok: false, error: 'Заповніть всі обов\'язкові поля' });
    }
    
    const checkUser = await pool.query('SELECT id FROM users WHERE phone = $1', [phone]);
    if (checkUser.rows.length > 0) {
      return res.json({ ok: false, error: 'Користувач з таким номером телефону вже зареєстрований!' });
    }
    
    const password_hash = await bcrypt.hash(password, 10);
    
    const result = await pool.query(
      `INSERT INTO users (name, phone, password_hash, role, car_make, plate_number, car_photo_url, is_verified) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, true) RETURNING id`,
      [name, phone, password_hash, role, carMake || null, plateNumber || null, carPhotoUrl || null]
    );
    res.json({ ok: true, userId: result.rows[0].id });
  } catch (err) {
    console.error('Registration error:', err.message);
    res.json({ ok: false, error: 'Server error: ' + err.message });
  }
});

// 🚀 Авторизація (Логін)
app.post('/api/auth/login', async (req, res) => {
  try {
    const { phone, password } = req.body;
    if (!phone || !password) {
      return res.json({ ok: false, error: 'Заповніть всі поля!' });
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
    
    const token = jwt.sign(
      { id: user.id, role: user.role, isAdmin: user.is_admin || false }, 
      JWT_SECRET, 
      { expiresIn: '7d' }
    );
    
    res.json({ ok: true, token, role: user.role, isAdmin: user.is_admin || false });
  } catch (err) {
    console.error('Login error:', err.message);
    res.json({ ok: false, error: 'Помилка сервера: ' + err.message });
  }
});

// 🚀 Отримання даних профілю
app.get('/api/profile', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.json({ ok: false, error: 'Нет токена авторизации' });
    
    const parts = authHeader.split(' ');
    const token = parts[1]; 
    const decoded = jwt.verify(token, JWT_SECRET);
    
    const result = await pool.query(
      'SELECT id, name, phone, role, car_make AS "carMake", plate_number AS "plateNumber", car_photo_url AS "carPhotoUrl" FROM users WHERE id = $1',
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

// 🚀 Оновлення даних профілю водія
app.put('/api/profile', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.json({ ok: false, error: 'Нет токена авторизации' });
    
    const parts = authHeader.split(' ');
    const token = parts[1]; 
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // 🔥 Четко принимаем camelCase поля из Android Retrofit-запроса
    const { name, phone, carMake, plateNumber } = req.body; 
    
    if (!name || !phone) {
      return res.json({ ok: false, error: 'Ім\'я та телефон обов\'язкові!' });
    }
    
    // 🔥 ИСПРАВЛЕНО: Лишняя запятая перед WHERE полностью удалена!
    await pool.query(
      'UPDATE users SET name = $1, phone = $2, car_make = $3, plate_number = $4 WHERE id = $5',
      [name, phone, carMake || null, plateNumber || null, decoded.id]
    );
    
    res.json({ ok: true });
  } catch (err) {
    console.error('Profile PUT error:', err.message);
    res.json({ ok: false, error: 'Помилка сервера при оновленні даних: ' + err.message });
  }
});

// ==========================================
// 🗺️ БЛОК ПОЕЗДОК (АКТИВНЫЕ МАРШРУТЫ)
// ==========================================

// 🚀 Створення активного маршруту на карті
app.post('/api/trips', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.json({ ok: false, error: 'Нет токена авторизации' });
    
    const parts = authHeader.split(' ');
    const token = parts[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    
    const { role, startLat, startLon, endLat, endLon, startAddress, endAddress } = req.body;
    
    await pool.query(
      "UPDATE active_trips SET status = 'cancelled' WHERE user_id = $1 AND status = 'searching'",
      [decoded.id]
    );
    
    const constStartAddress = startAddress || "Точка на карті (Старт)";
    const constEndAddress = endAddress || "Точка на карті (Фініш)";
    
    const result = await pool.query(
      `INSERT INTO active_trips (user_id, role, start_lat, start_lon, end_lat, end_lon, start_address, end_address) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`,
      [decoded.id, role, startLat, startLon, endLat, endLon, constStartAddress, constEndAddress]
    );
    
    res.json({ ok: true, tripId: result.rows[0].id });
    
  } catch (err) {
    console.error('Trip creation error:', err.message);
    res.json({ ok: false, error: 'Помилка сервера при створенні маршруту: ' + err.message });
  }
});

// 🚀 Поиск попутных водителей для пассажира
app.get('/api/trips/drivers', async (req, res) => {
  try {
    const { startLat, startLon, endLat, endLon } = req.query;
    if (!startLat || !startLon || !endLat || !endLon) {
        return res.json({ ok: false, error: 'Пропущені координати пасажира' });
    }
    const pStartLat = parseFloat(startLat);
    const pStartLon = parseFloat(startLon);
    const pEndLat = parseFloat(endLat);
    const pEndLon = parseFloat(endLon);
    
    const result = await pool.query(
      `SELECT t.id AS "tripId", t.user_id AS "driverId", t.start_lat AS "startLat", t.start_lon AS "startLon", 
              t.end_lat AS "endLat", t.end_lon AS "endLon", t.start_address AS "startAddress", t.end_address AS "endAddress",
              u.name, u.phone, u.car_make AS "carMake", u.plate_number AS "plateNumber", u.car_photo_url AS "carPhotoUrl"
       FROM active_trips t
       JOIN users u ON t.user_id = u.id
       WHERE t.role = 'driver' AND t.status = 'searching'
         AND calculate_distance($1, $2, t.start_lat, t.start_lon) <= 5.0
         AND calculate_distance($3, $4, t.end_lat, t.end_lon) <= 5.0`,
      [pStartLat, pStartLon, pEndLat, pEndLon]
    );
    res.json({ ok: true, drivers: result.rows });
  } catch (err) {
    console.error('Get drivers error:', err.message);
    res.json({ ok: false, error: 'Помилка сервера пошуку водіїв: ' + err.message });
  }
});

// ==========================================
// 💰 БЛОК СТАВОК (ТОРГИ И ПУШ-СИСТЕМА ДЛЯ MVP)
// ==========================================

// 🚀 Пасажир робить ставку вибраному водію
app.post('/api/bids', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.json({ ok: false, error: 'Нет токена авторизации' });
    const parts = authHeader.split(' ');
    const token = parts[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    const { tripId, driverId, proposedPrice, passengerCount } = req.body;
    
    const checkAttempts = await pool.query(
      `SELECT COUNT(*)::int AS count FROM ride_bids 
       WHERE trip_id = $1 AND passenger_id = $2 AND driver_id = $3`,
      [tripId, decoded.id, driverId]
    );
    
    const currentAttempts = checkAttempts.rows[0].count;
    if (currentAttempts >= 3) {
      return res.json({ 
        ok: false, 
        error: 'Ви вичерпали ліміт ставок (макс. 3) для цього водія!' 
      });
    }
    const nextAttemptNumber = currentAttempts + 1;
    
    const result = await pool.query(
      `INSERT INTO ride_bids (trip_id, passenger_id, driver_id, proposed_price, passenger_count, attempt_number, status)
       VALUES ($1, $2, $3, $4, $5, $6, 'pending') RETURNING id`,
      [tripId, decoded.id, driverId, proposedPrice, passengerCount, nextAttemptNumber]
    );
    res.json({ ok: true, bidId: result.rows[0].id, attempt: nextAttemptNumber });
  } catch (err) {
    console.error('Bid creation error:', err.message);
    res.json({ ok: false, error: 'Помилка сервера при створенні ставки: ' + err.message });
  }
});

// 🚀 Водитель запрашивает входящие ставки для своей поездки
app.get('/api/bids/driver/incoming', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.json({ ok: false, error: 'Немає токена авторизації' });
    
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    const { tripId } = req.query; 
    if (!tripId) {
      return res.json({ ok: false, error: 'Пропущений tripId водія' });
}
const result = await pool.query(
SELECT b.id AS "bidId", b.trip_id AS "passengerTripId", b.proposed_price AS "proposedPrice", b.passenger_count AS "passengerCount", u.name AS "passengerName", t.start_address AS "startAddress" FROM ride_bids b JOIN users u ON b.passenger_id = u.id JOIN active_trips t ON b.trip_id = t.id WHERE b.driver_id = $1 AND b.status = 'pending',
[decoded.id]
);
res.json({ ok: true, bids: result.rows });
} catch (err) {
console.error('Incoming bids error:', err.message);
res.json({ ok: false, error: 'Помилка сервера радара водія: ' + err.message });
}
});
// 🚀 Водитель принимает или отклоняет ставку
app.post('/api/bids/respond', async (req, res) => {
try {
const { bidId, status } = req.body;
if (!bidId || !status) {
return res.json({ ok: false, error: 'Неповні дані запиту' });
}
await pool.query(
"UPDATE ride_bids SET status = $1 WHERE id = $2",
[status, bidId]
);
res.json({ ok: true });
} catch (err) {
console.error('Respond bid error:', err.message);
res.json({ ok: false, error: err.message });
}
});
// 🚀 Регулярный опрос статуса ставки для Пассажира
app.get('/api/bids/status/passenger', async (req, res) => {
try {
const { tripId } = req.query;
if (!tripId) {
return res.json({ ok: false, error: 'Пропущений tripId' });
}
const result = await pool.query(
SELECT b.status, u.phone AS "driverPhone" FROM ride_bids b JOIN users u ON b.driver_id = u.id WHERE b.trip_id = $1 ORDER BY b.id DESC LIMIT 1,
[tripId]
);
if (result.rows.length === 0) {
return res.json({ ok: true, status: 'pending', driverPhone: null });
}
const topBid = result.rows[0];
res.json({
ok: true,
status: topBid.status,
driverPhone: topBid.status === 'accepted' ? topBid.driverPhone : null
});
} catch (err) {
console.error('Status error:', err.message);
res.json({ ok: false, error: err.message });
}
});
// ==========================================
// 🚀 ЗАПУСКАЕМ СЕРВЕР
// ==========================================
app.listen(PORT, () => {
console.log(🚀 Server is running smoothly on port ${PORT});
});


