require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bcrypt = require('bcryptjs'); 
const { Pool } = require('pg');
const path = require('path');

const app = express();
app.use(bodyParser.json());
app.use(cors());

const JWT_SECRET = process.env.JWT_SECRET || 'supersecretkey';
const PORT = process.env.PORT || 10000;

// Настройка пула подключений к Supabase (PostgreSQL)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Проверка работоспособности сервера (Health Check)
app.get('/api/health', (req, res) => {
  res.json({ ok: true });
});

// Перенаправление с главной страницы на админку
app.get('/', (req, res) => {
  res.redirect('/admin');
});

// ==========================================
// 🖥️ БЛОК ВЕБ-ПАНЕЛИ АДМИНИСТРАТОРА (ВШИТ НАПРЯМУЮ)
// ==========================================
app.get('/admin', (req, res) => {
  res.send(`
<!DOCTYPE html>
<html lang="uk">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Панель Admin Diway</title>
    <style>
        body { font-family: sans-serif; background-color: #F4F6F9; margin: 0; padding: 0; color: #212121; }
        .auth-container, .dashboard-container { max-width: 500px; margin: 80px auto; background: #FFFFFF; padding: 40px; border-radius: 24px; box-shadow: 0 10px 30px rgba(0,0,0,0.05); }
        .dashboard-container { max-width: 800px; margin: 40px auto; display: none; }
        h2 { text-align: center; margin-bottom: 24px; color: #0D47A1; }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 8px; font-weight: bold; font-size: 14px; color: #757575; }
        input { width: 100%; height: 54px; padding: 0 16px; border: 1.5px solid #E0E0E0; border-radius: 12px; font-size: 16px; box-sizing: border-box; }
        button { width: 100%; height: 56px; background-color: #0D47A1; color: #FFFFFF; border: none; border-radius: 12px; font-size: 16px; font-weight: bold; cursor: pointer; }
        .driver-card { background: #FFFFFF; border: 1.5px solid #E0E0E0; border-radius: 16px; padding: 20px; margin-bottom: 16px; display: flex; justify-content: space-between; align-items: center; }
        .badge { display: inline-block; padding: 4px 12px; background: #E3F2FD; color: #0D47A1; border-radius: 8px; font-weight: bold; font-size: 12px; }
        .btn-approve { background-color: #10B981; width: auto; padding: 0 20px; height: 44px; color: #fff; border: none; border-radius: 8px; font-weight: bold; cursor: pointer;}
        .no-data { text-align: center; color: #757575; font-style: italic; margin-top: 40px; }
    </style>
</head>
<body>
    <div class="auth-container" id="authBlock">
        <h2>Вхід до Diway Admin</h2>
        <div class="form-group">
            <label>Номер телефону</label>
            <input type="text" id="adminPhone" placeholder="+380...">
        </div>
        <div class="form-group">
            <label>Код безпеки (2FA)</label>
            <input type="text" id="adminCode" placeholder="777999" maxlength="6" style="text-align: center; font-weight: bold;">
        </div>
        <button onclick="loginAdmin()">ПІДТВЕРДИТИ ВХІД</button>
    </div>
    <div class="dashboard-container" id="dashboardBlock">
        <h2>Панель Модерації Водіїв</h2>
        <div id="driversList">
            <div class="no-data">Завантаження заявок...</div>
        </div>
    </div>
    <script>
        let adminToken = '';
        async function loginAdmin() {
            const phone = document.getElementById('adminPhone').value.trim();
            const code = document.getElementById('adminCode').value.trim();
            if(!phone || !code) { alert('Заповніть всі поля!'); return; }
            try {
                const response = await fetch('/api/admin/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ phone, code })
                });
                const data = await response.json();
                if (data.ok) {
                    adminToken = data.token;
                    document.getElementById('authBlock').style.display = 'none';
                    document.getElementById('dashboardBlock').style.display = 'block';
                    loadUnverifiedDrivers();
                } else { alert('Відмовлено: ' + data.error); }
            } catch (err) { alert('Помилка мережі при вході'); }
        }
        async function loadUnverifiedDrivers() {
            try {
                const response = await fetch('/api/admin/unverified-drivers', {
                    headers: { 'Authorization': 'Bearer ' + adminToken }
                });
                const data = await response.json();
                const listDiv = document.getElementById('driversList');
                listDiv.innerHTML = '';
                if (data.ok && data.drivers && data.drivers.length > 0) {
                    data.drivers.forEach(driver => {
                        const card = document.createElement('div');
                        card.className = 'driver-card';
                        card.innerHTML = '<div class="driver-info"><h3>' + driver.name + '</h3><p>Тел: ' + driver.phone + '</p><p><span class="badge">' + (driver.carMake || 'Авто') + ' (' + (driver.plateNumber || 'Б/Н') + ')</span></p></div><div class="actions"><button class="btn-approve" onclick="verifyDriver(' + driver.id + ')">ВЕРИФІКУВАТИ</button></div>';
                        listDiv.appendChild(card);
                    });
                } else { listDiv.innerHTML = '<div class="no-data">Немає нових заявок. Все перевірено!</div>'; }
            } catch (err) { document.getElementById('driversList').innerHTML = '<div class="no-data">Помилка завантаження</div>'; }
        }
        async function verifyDriver(driverId) {
            try {
                const response = await fetch('/api/admin/verify-driver', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + adminToken },
                    body: JSON.stringify({ driverId })
                });
                const data = await response.json();
                if (data.ok) { alert('Водія успішно верифіковано!'); loadUnverifiedDrivers(); } else { alert('Помилка: ' + data.error); }
            } catch (err) { alert('Помилка сервера'); }
        }
    </script>
</body>
</html>
  `);
});

// ==========================================
// 🔐 БЛОК АВТОРИЗАЦИИ И ПОЛЬЗОВАТЕЛЕЙ
// ==========================================
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, phone, role, password, carMake, plateNumber, carPhotoUrl } = req.body;
    if (!name || !phone || !password || !role) return res.json({ ok: false, error: 'Заповніть обов\'язкові поля' });
    
    const checkUser = await pool.query('SELECT id FROM users WHERE phone = $1', [phone]);
    if (checkUser.rows.length > 0) return res.json({ ok: false, error: 'Користувач вже зареєстрований!' });
    
    const password_hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      `INSERT INTO users (name, phone, password_hash, role, car_make, plate_number, car_photo_url, is_verified) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, true) RETURNING id`,
      [name, phone, password_hash, role, carMake || null, plateNumber || null, carPhotoUrl || null]
    );
    res.json({ ok: true, userId: result.rows.id });
  } catch (err) {
    res.json({ ok: false, error: err.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { phone, password } = req.body;
    if (!phone || !password) return res.json({ ok: false, error: 'Заповніть всі поля!' });
    
    const result = await pool.query('SELECT * FROM users WHERE phone = $1', [phone]);
    if (result.rows.length === 0) return res.json({ ok: false, error: 'Користувача не знайдено' });
    
    const user = result.rows[0]; 
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.json({ ok: false, error: 'Невірний пароль' });
    
    const token = jwt.sign({ id: user.id, role: user.role, isAdmin: user.is_admin || false }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ ok: true, token, role: user.role, isAdmin: user.is_admin || false });
  } catch (err) {
    res.json({ ok: false, error: err.message });
  }
});

app.get('/api/profile', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.json({ ok: false, error: 'Нет токена' });
    const token = authHeader.split(' ')[1]; 
    const decoded = jwt.verify(token, JWT_SECRET);
    
    const result = await pool.query(
      `SELECT id, name, phone, role, car_make AS "carMake", plate_number AS "plateNumber", 
              created_at AS "createdAt", subscription_expires_at AS "subscriptionExpiresAt" 
       FROM users WHERE id = $1`,
      [decoded.id]
    );
    res.json({ ok: true, user: result.rows[0] });
  } catch (err) {
    res.json({ ok: false, error: err.message });
  }
});

app.put('/api/profile', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.json({ ok: false, error: 'Нет токена' });
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    const { name, phone, carMake, plateNumber } = req.body;
    
    await pool.query(
      'UPDATE users SET name=$1, phone=$2, car_make=$3, plate_number=$4 WHERE id=$5',
      [name, phone, carMake, plateNumber, decoded.id]
    );
    res.json({ ok: true });
  } catch (err) {
    res.json({ ok: false, error: err.message });
  }
});

// Админ логин на странице
app.post('/api/admin/login', async (req, res) => {
try {
const { phone, code } = req.body;
if (code !== '777999') return res.json({ ok: false, error: 'Невірний 2FA код!' });
const result = await pool.query('SELECT * FROM users WHERE phone = $1', [phone]);
if (result.rows.length === 0) return res.json({ ok: false, error: 'Користувача не знайдено' });
const user = result.rows[0];
const token = jwt.sign({ id: user.id, role: 'admin', isAdmin: true }, JWT_SECRET, { expiresIn: '2h' });
res.json({ ok: true, token });
} catch (err) { res.json({ ok: false, error: err.message }); }
});
// Админ: Получить невыверенных водителей (КАВЫЧКИ SQL ПОЛНОСТЬЮ ИСПРАВЛЕНЫ)
app.get('/api/admin/unverified-drivers', async (req, res) => {
try {
const authHeader = req.headers['authorization'];
const token = authHeader.split(' ')[1];
const decoded = jwt.verify(token, JWT_SECRET);
if (!decoded.isAdmin) return res.json({ ok: false, error: 'Ви не адмін.' });
const result = await pool.query(SELECT id, name, phone, car_make AS "carMake", plate_number AS "plateNumber"  FROM users  WHERE role='driver' AND is_verified=false  ORDER BY id DESC);
res.json({ ok: true, drivers: result.rows });
} catch (err) { res.json({ ok: false, error: err.message }); }
});
// Админ: Одобрить водителя
app.post('/api/admin/verify-driver', async (req, res) => {
try {
const authHeader = req.headers['authorization'];
const token = authHeader.split(' ')[1];
const decoded = jwt.verify(token, JWT_SECRET);
if (!decoded.isAdmin) return res.json({ ok: false, error: 'Заборонено' });
const { driverId } = req.body;
await pool.query('UPDATE users SET is_verified = true WHERE id = $1', [driverId]);
res.json({ ok: true });
} catch (err) { res.json({ ok: false, error: err.message }); }
});
// ==========================================
// 🗺️ БЛОК ПОЕЗДОК (АКТИВНЫЕ МАРШРУТЫ)
// ==========================================
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
INSERT INTO active_trips (user_id, role, start_lat, start_lon, end_lat, end_lon, start_address, end_address)  VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id,
[decoded.id, role, startLat, startLon, endLat, endLon, constStartAddress, constEndAddress]
);
res.json({ ok: true, tripId: result.rows[0].id });
} catch (err) {
console.error('Trip creation error:', err.message);
res.json({ ok: false, error: 'Помилка сервера при створенні маршруту: ' + err.message });
}
});
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
SELECT t.id AS "tripId", t.user_id AS "driverId", t.start_lat AS "startLat", t.start_lon AS "startLon",  t.end_lat AS "endLat", t.end_lon AS "endLon", t.start_address AS "startAddress", t.end_address AS "endAddress", u.name, u.phone, u.car_make AS "carMake", u.plate_number AS "plateNumber" FROM active_trips t JOIN users u ON t.user_id = u.id WHERE t.role = 'driver' AND t.status = 'searching' AND calculate_distance($1, $2, t.start_lat, t.start_lon) <= 5.0 AND calculate_distance($3, $4, t.end_lat, t.end_lon) <= 5.0,
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
app.post('/api/bids', async (req, res) => {
try {
const authHeader = req.headers['authorization'];
if (!authHeader) return res.json({ ok: false, error: 'Нет токена авторизации' });
const parts = authHeader.split(' ');
const token = parts[1];
const decoded = jwt.verify(token, JWT_SECRET);
const { tripId, driverId, proposedPrice, passengerCount } = req.body;
const checkAttempts = await pool.query(
"SELECT COUNT(*)::int AS count FROM ride_bids WHERE trip_id = $1 AND passenger_id = $2 AND driver_id = $3",
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
INSERT INTO ride_bids (trip_id, passenger_id, driver_id, proposed_price, passenger_count, attempt_number, status) VALUES ($1, $2, $3, $4, $5, $6, 'pending') RETURNING id,
[tripId, decoded.id, driverId, proposedPrice, passengerCount, nextAttemptNumber]
);
res.json({ ok: true, bidId: result.rows[0].id, attempt: nextAttemptNumber });
} catch (err) {
console.error('Bid creation error:', err.message);
res.json({ ok: false, error: 'Помилка сервера при створенні ставки: ' + err.message });
}
});
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
SELECT b.id AS "bidId", b.trip_id AS "passengerTripId", b.proposed_price AS "proposedPrice",  b.passenger_count AS "passengerCount", u.name AS "passengerName", t.start_address AS "startAddress" FROM ride_bids b JOIN users u ON b.passenger_id = u.id JOIN active_trips t ON b.trip_id = t.id WHERE b.driver_id = $1 AND b.status = 'pending',
[decoded.id]
);
res.json({ ok: true, bids: result.rows });
} catch (err) {
console.error('Incoming bids error:', err.message);
res.json({ ok: false, error: 'Помилка сервера радара водія: ' + err.message });
}
});
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
app.listen(PORT, () => {
console.log(🚀 Server is running smoothly on port ${PORT});
});
