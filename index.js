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
app.use(express.urlencoded({ extended: true }));

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

// Настройка Multer для приема изображений авто
const multer = require('multer');
const upload = multer({
  limits: { fileSize: 5 * 1024 * 1024 }, 
  storage: multer.memoryStorage()
});

// 🚀 POST /api/upload/car-photo — Загрузка фотографии автомобиля
app.post('/api/upload/car-photo', upload.single('photo'), async (req, res) => {
  try {
    if (!req.file) {
      return res.json({ ok: false, error: 'Файл не завантажено' });
    }
    const base64Image = `data:${req.file.mimetype};base64,${req.file.buffer.toString('base64')}`;
    res.json({ ok: true, carPhotoUrl: base64Image });
  } catch (err) {
    console.error('Upload error:', err.message);
    res.json({ ok: false, error: 'Помилка сервера при завантаженні фото: ' + err.message });
  }
});

// ==========================================
// 🔐 БЛОК АВТОРИЗАЦИИ И ПОЛЬЗОВАТЕЛЕЙ
// ==========================================

app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, phone, role, password, carMake, plateNumber, deviceId } = req.body;
    if (!name || !phone || !password || !role || !deviceId) {
      return res.json({ ok: false, error: 'Заповніть обов\'язкові поля та ID пристрою!' });
    }
    
    const checkUser = await pool.query('SELECT id FROM users WHERE phone = \$1', [phone]);
    if (checkUser.rows.length > 0) return res.json({ ok: false, error: 'Користувач вже зареєстрований!' });
    
    const checkDevice = await pool.query('SELECT id FROM device_trials WHERE device_id = \$1', [deviceId]);
    if (checkDevice.rows.length === 0) {
      await pool.query('INSERT INTO device_trials (device_id, first_registered_at) VALUES (\$1, NOW())', [deviceId]);
    }
    const password_hash = await bcrypt.hash(password, 10);
    
    const result = await pool.query(
      `INSERT INTO users (name, phone, password_hash, role, car_make, plate_number, is_verified, device_id) 
       VALUES ($1, $2, $3, $4, $5, $6, true, $7) RETURNING id`,
      [name, phone, password_hash, role, carMake || null, plateNumber || null, deviceId]
    );
    res.json({ ok: true, userId: result.rows.id });
  } catch (err) {
    console.error('Registration error:', err.message);
    res.json({ ok: false, error: err.message });
  }
});

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

app.get('/api/profile', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.json({ ok: false, error: 'Нет токена' });
    const token = authHeader.replace(/^Bearer\s+/, '').trim(); 
    const decoded = jwt.verify(token, JWT_SECRET);
    
    const result = await pool.query(
      `SELECT u.id, u.name, u.phone, u.role, u.car_make, u.plate_number, 
              u.subscription_expires_at, u.device_id, u.is_verified,
              d.first_registered_at
       FROM users u
       LEFT JOIN device_trials d ON u.device_id = d.device_id
       WHERE u.id = $1`,
      [decoded.id]
    );
    
    if (result.rows.length === 0) return res.json({ ok: false, error: 'Користувача не знайдено' });
    const user = result.rows[0];
    
    const now = new Date();
    const deviceRegisteredAt = user.first_registered_at ? new Date(user.first_registered_at) : new Date();
    const subscriptionExpiresAt = user.subscription_expires_at ? new Date(user.subscription_expires_at) : null;
    
    let daysLeft = 0;
    let isBlocked = false;
    const trialPeriodMs = 30 * 24 * 60 * 60 * 1000; // 30 дней триала
    const trialExpiryDate = new Date(deviceRegisteredAt.getTime() + trialPeriodMs);
    
    if (subscriptionExpiresAt && now < subscriptionExpiresAt) {
      const msLeft = subscriptionExpiresAt - now;
      daysLeft = Math.ceil(msLeft / (1000 * 24 * 60 * 60));
      isBlocked = false;
    } else if (now < trialExpiryDate) {
      const msLeft = trialExpiryDate - now;
      daysLeft = Math.ceil(msLeft / (1000 * 24 * 60 * 60));
      isBlocked = false;
    } else {
      daysLeft = 0;
      isBlocked = true;
    }

    if (user.is_verified === false || user.is_verified === 0 || user.is_verified === 'false') {
      daysLeft = 0;
      isBlocked = true;
    }
       
    res.json({ 
      ok: true, 
      user: {
        id: user.id,
        name: user.name,
        phone: user.phone,
        role: user.role,
        carMake: user.car_make,       
        plateNumber: user.plate_number, 
        daysLeft: daysLeft,
        isBlocked: isBlocked
      }
    });
  } catch (err) {
    console.error('Profile GET error:', err.message);
    res.json({ ok: false, error: 'Помилка авторизації: ' + err.message });
  }
});

app.put('/api/profile', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.json({ ok: false, error: 'Нет токена авторизации' });
    const token = authHeader.replace(/^Bearer\s+/, '').trim(); 
    const decoded = jwt.verify(token, JWT_SECRET);
    const { name, phone, carMake, plateNumber, carPhotoUrl } = req.body;
    
    await pool.query(
      'UPDATE users SET name=$1, phone=$2, car_make=$3, plate_number=$4, car_photo_url=$5 WHERE id=$6',
      [name, phone, carMake, plateNumber, carPhotoUrl || null, decoded.id]
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

app.post('/api/trips', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.json({ ok: false, error: 'Нет токена авторизации' });
    const token = authHeader.replace(/^Bearer\s+/, '').trim();
    const decoded = jwt.verify(token, JWT_SECRET);
    
    const checkUserStatus = await pool.query('SELECT is_verified FROM users WHERE id = \$1', [decoded.id]);
    if (checkUserStatus.rows.length === 0 || checkUserStatus.rows[0].is_verified === false) {
      return res.json({ ok: false, error: 'Доступ обмежено! Ваш аккаунт заблоковано адміністрацією.' });
    }
    
    const { role, startLat, startLon, endLat, endLon, startAddress, endAddress, departureTime } = req.body;
    
    const finalStartAddress = startAddress || "Точка на карті (Старт)";
    const finalEndAddress = endAddress || "Точка на карті (Фініш)";
    const finalDepartureTime = departureTime || new Date().toISOString();
    
    const result = await pool.query(
      `INSERT INTO active_trips (user_id, role, start_lat, start_lon, end_lat, end_lon, start_address, end_address, status, departure_time) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'searching', $9) 
       ON CONFLICT (user_id) 
       DO UPDATE SET 
          start_lat = EXCLUDED.start_lat, 
          start_lon = EXCLUDED.start_lon,
          end_lat = EXCLUDED.end_lat,
          end_lon = EXCLUDED.end_lon,
          start_address = EXCLUDED.start_address,
          end_address = EXCLUDED.end_address,
          departure_time = EXCLUDED.departure_time,
          status = 'searching'
       RETURNING id`,
      [decoded.id, role, startLat, startLon, endLat, endLon, finalStartAddress, finalEndAddress, finalDepartureTime]
    );
    
    res.json({ ok: true, tripId: result.rows[0].id });
  } catch (err) {
    console.error('Trip creation error:', err.message);
    res.json({ ok: false, error: 'Помилка сервера при створенні маршруту: ' + err.message });
  }
});

// 🚀 РОЗУМНИЙ РАДАР: Видача Дніпровських координат в camelCase з часовим вікном +/- 12 годин
app.get('/api/trips/drivers', async (req, res) => {
  try {
    const sLat = req.query.startLat || req.query.start_lat;
    const sLon = req.query.startLon || req.query.start_lon;
    if (!sLat || !sLon) {
        return res.json({ ok: false, error: 'Пропущені координати пасажира' });
    }
    const pStartLat = parseFloat(sLat);
    const pStartLon = parseFloat(sLon);
    
    const latDelta = 0.025; 
    const lonDelta = 0.03;
    
    const result = await pool.query(
      `SELECT t.id AS "tripId", t.user_id::int AS "driverId", t.start_lat AS "startLat", t.start_lon AS "startLon", 
t.end_lat AS "endLat", t.end_lon AS "endLon", t.start_address AS "startAddress", t.end_address AS "endAddress",
t.departure_time AS "departureTime",
u.name, u.phone, u.car_make AS "carMake", u.plate_number AS "plateNumber"
FROM active_trips t
JOIN users u ON t.user_id = u.id
WHERE t.role = 'driver'
AND t.status = 'searching'
AND u.is_verified = true
AND t.start_lat BETWEEN $1 - $2 AND $1 + $2
AND t.start_lon BETWEEN $3 - $4 AND $3 + $4
AND t.departure_time BETWEEN NOW() - INTERVAL '12 hours' AND NOW() + INTERVAL '12 hours'
ORDER BY t.id DESC`,
[pStartLat, latDelta, pStartLon, lonDelta]
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
const token = authHeader.replace(/^Bearer\s+/, '').trim();
const decoded = jwt.verify(token, JWT_SECRET);
const { tripId, driverId, proposedPrice, passengerCount } = req.body;
const checkAttempts = await pool.query(
SELECT COUNT(*)::int AS count FROM ride_bids WHERE trip_id = $1 AND passenger_id = $2 AND driver_id = $3,
[tripId, decoded.id, driverId]
);
const currentAttempts = checkAttempts.rows[0].count;
const checkDriverStatus = await pool.query('SELECT is_verified FROM users WHERE id = $1', [driverId]);
if (checkDriverStatus.rows.length === 0 || !checkDriverStatus.rows[0].is_verified) {
return res.json({ ok: false, error: 'Доступ обмежено! Цей водій заблокований адміністрацією Diway.' });
}
if (currentAttempts >= 3) {
return res.json({ ok: false, error: 'Ви вичерпали ліміт ставок (макс. 3) для цього водія!' });
}
const nextAttemptNumber = currentAttempts + 1;
const result = await pool.query(
INSERT INTO ride_bids (trip_id, passenger_id, driver_id, proposed_price, passenger_count, attempt_number, status) VALUES ($1, $2, $3, $4, $5, $6, 'pending') RETURNING id,
[tripId, decoded.id, driverId, proposedPrice, passengerCount, nextAttemptNumber]
);
res.json({ ok: true, bidId: result.rows.id, attempt: nextAttemptNumber });
} catch (err) {
console.error('Bid creation error:', err.message);
res.json({ ok: false, error: 'Помилка сервера при створенні ставки: ' + err.message });
}
});
app.get('/api/bids/driver/incoming', async (req, res) => {
try {
const authHeader = req.headers['authorization'];
if (!authHeader) return res.json({ ok: false, error: 'Немає токена авторизації' });
const token = authHeader.replace(/^Bearer\s+/, '').trim();
const decoded = jwt.verify(token, JWT_SECRET);
const { tripId } = req.query;
if (!tripId) return res.json({ ok: false, error: 'Пропущений tripId водія' });
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
app.post('/api/bids/respond', async (req, res) => {
try {
const { bidId, status } = req.body;
if (!bidId || !status) return res.json({ ok: false, error: 'Неповні дані запиту' });
await pool.query("UPDATE ride_bids SET status = $1 WHERE id = $2", [status, bidId]);
res.json({ ok: true });
} catch (err) {
console.error('Respond bid error:', err.message);
res.json({ ok: false, error: err.message });
}
});
app.get('/api/bids/status/passenger', async (req, res) => {
try {
const { tripId } = req.query;
if (!tripId) return res.json({ ok: false, error: 'Пропущений tripId' });
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
driverPhone: topBid.status === "accepted" ? topBid.driverPhone : null
});
} catch (err) {
console.error('Status error:', err.message);
res.json({ ok: false, error: err.message });
}
});
// ==========================================
// 🖥️ БЛОК ВЕБ-ПАНЕЛИ АДМИНИСТРАТОРА
// ==========================================
app.get('/', (req, res) => { res.redirect('/admin'); });
app.get('/admin', (req, res) => {
let html = '';
html += 'Панель Admin Diway';
html += 'body{font-family:sans-serif;background-color:#F4F6F9;margin:0;padding:0;color:#212121;}';
html += '.auth-container,.dashboard-container{max-width:500px;margin:40px auto;background:#FFFFFF;padding:40px;border-radius:24px;box-shadow:0 10px 30px rgba(0,0,0,0.05);}';
html += '.dashboard-container{max-width:800px;margin:20px auto;display:none;}';
html += 'h2{text-align:center;margin-bottom:24px;color:#0D47A1;}';
html += '.form-group{margin-bottom:20px;}';
html += 'label{display:block;margin-bottom:8px;font-weight:bold;font-size:14px;color:#757575;}';
html += 'input{width:100%;height:54px;padding:0 16px;border:1.5px solid #E0E0E0;border-radius:12px;font-size:16px;box-sizing:border-box;}';
html += 'button{width:100%;height:56px;background-color:#0D47A1;color:#FFFFFF;border:none;border-radius:12px;font-size:16px;font-weight:bold;cursor:pointer;}';
html += '.driver-card{background:#FFFFFF;border:1.5px solid #E0E0E0;border-radius:16px;padding:20px;margin-bottom:16px;display:flex;justify-content:space-between;align-items:center;}';
html += '.badge{display:inline-block;padding:4px 12px;background:#E3F2FD;color:#0D47A1;border-radius:8px;font-weight:bold;font-size:12px;}';
html += '.btn-approve{background-color:#10B981;width:auto;padding:0 20px;height:44px;color:#fff;border:none;border-radius:8px;font-weight:bold;cursor:pointer;}';
html += '.no-data{text-align:center;color:#757575;font-style:italic;margin-top:20px;}';
html += '.admin-section{background:#F8F9FA;padding:20px;border-radius:16px;border:1.5px solid #E0E0E0;margin-bottom:24px;}';
html += '';
html += 'Вхід до Diway Admin';
html += 'Номер телефону';
html += 'Код безпеки (2FA)';
html += 'ПІДТВЕРДИТИ ВХІД';
html += 'Панель Адміністратора Diway';
html += '';
html += ' ';
html += ' 📊 ВСЬОГО УНІКАЛЬНИХ ПРИСТРОЇВ';
html += ' 0';
html += ' ';
html += ' ';
html += ' 📈 НОВИХ ПРИСТРОЇВ (ЗА СЬОГОДНІ)';
html += ' 0';
html += ' ';
html += '';
html += '🛠️ Ручне керування підписками ';
html += 'Введіть номер телефону смартфона, щоб нарахувати йому тестовий БЕЗЛІМІТ до 2050 року';
html += '';
html += '';
html += 'ВИДАТИ БЕЗЛІМІТ';
html += '';
html += '📋 Усі зареєстровані користувачі та керування доступом';
html += 'Завантаження пасажирів...';
html += 'Завантаження водіїв...';
html += '';
html += 'let adminToken = "";';
html += 'async function loginAdmin() {';
html += ' const phone = document.getElementById("adminPhone").value.trim();';
html += ' const code = document.getElementById("adminCode").value.trim();';
html += ' if(!phone || !code) { alert("Заповніть всі поля!"); return; }';
html += ' try {';
html += ' const response = await fetch("/api/admin/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ phone, code }) });';
html += ' const data = await response.json();';
html += ' if (data.ok) { adminToken = data.token; document.getElementById("authBlock").style.display = "none"; document.getElementById("dashboardBlock").style.display = "block"; loadUnverifiedDrivers(); }';
html += ' else { alert("Відмовлено: " + data.error); }';
html += ' } catch (err) { alert("Помилка мережі при вході"); }';
html += '}';
html += `async function loadUnverifiedDrivers() {
try {
const response = await fetch("/api/admin/unverified-drivers", { headers: { "Authorization": "Bearer " + adminToken } });
const data = await response.json();
if (data.stats) {
document.getElementById("statTotalUsers").innerText = data.stats.totalDevices || 0;
document.getElementById("statTodayUsers").innerText = data.stats.todayDevices || 0;
}
if (!data.ok) {
document.getElementById("driversList").innerHTML = "Помилка сервера: " + data.error + "";
return;
}
const listDiv = document.getElementById("driversList"); listDiv.innerHTML = "";
if (data.drivers && data.drivers.length > 0) {
data.drivers.forEach(driver => {
const card = document.createElement("div"); card.className = "driver-card";
let isDriverActive = driver.isVerified === true || driver.isVerified === 'true' || driver.isVerified === 1;
let statusBadge = isDriverActive ? "Активний" : "ЗАБЛОКОВАНИЙ";
let actionButton = isDriverActive ? "ЗАБЛОКУВАТИ" : "РОЗБЛОКУВАТИ";
card.innerHTML = "" + driver.name + " " + statusBadge + "Тел: " + driver.phone + "" + (driver.carMake || "Авто") + " (" + (driver.plateNumber || "Б/Н") + ")" + actionButton + "";
listDiv.appendChild(card);
});
} else { listDiv.innerHTML = "Водіїв не знайдено."; }
const passDiv = document.getElementById("passengersList"); passDiv.innerHTML = "";
if (data.passengers && data.passengers.length > 0) {
data.passengers.forEach(pass => {
const card = document.createElement("div"); card.className = "driver-card";
let isPassengerActive = pass.isVerified === true || pass.isVerified === 'true' || pass.isVerified === 1;
let statusBadge = isPassengerActive ? "Активний" : "ЗАБЛОКОВАНИЙ";
let actionButton = isPassengerActive ? "ЗАБЛОКУВАТИ" : "РОЗБЛОКУВАТИ";
card.innerHTML = "" + pass.name + " " + statusBadge + "Тел: " + pass.phone + "" + actionButton + "";
passDiv.appendChild(card);
});
} else { passDiv.innerHTML = "Пасажирів не знайдено."; }
} catch (err) { alert("Помилка завантаження адмінки"); }
};`;
html += 'async function toggleDriverBlock(driverId, setActivate) {';
html += ' let confirmAction = confirm(setActivate ? "Розблокувати?" : "🚨 ЗАБЛОКУВАТИ?");';
html += ' if (!confirmAction) return;';
html += ' try {';
html += ' const response = await fetch("/api/admin/verify-driver", { method: "POST", headers: { "Content-Type": "application/json", "Authorization": "Bearer " + adminToken }, body: JSON.stringify({ driverId, activeStatus: setActivate }) });';
html += ' const data = await response.json();';
html += ' if (data.ok) { loadUnverifiedDrivers(); } else { alert(data.error); }';
html += ' } catch (err) { alert("Помилка сервера"); }';
html += '}';
html += 'async function grantManualSubscription() {';
html += ' const phone = document.getElementById("targetUserPhone").value.trim();';
html += ' if(!phone) return;';
html += ' try {';
html += ' const response = await fetch("/api/admin/manual-subscription", { method: "POST", headers: { "Content-Type": "application/json", "Authorization": "Bearer " + adminToken }, body: JSON.stringify({ phone }) });';
html += ' const data = await response.json();';
html += ' if(data.ok) { alert("🟢 Безліміт активовано!"); document.getElementById("targetUserPhone").value = ""; }';
// 🟢 ИСПРАВЛЕНО: Украинский апостроф экранирован как '
html += ' } catch(err) { alert("Помилка з'єднання з сервером"); }';
html += '}';
html += '';
res.send(html);
});
app.post('/api/admin/login', async (req, res) => {
try {
const { phone, code } = req.body;
if (code !== '777999') return res.json({ ok: false, error: 'Невірний код!' });
const result = await pool.query('SELECT * FROM users WHERE phone = $1', [phone.trim()]);
if (result.rows.length === 0) return res.json({ ok: false, error: 'Користувача не знайдено' });
const user = result.rows[0];
if (!user.is_admin) return res.json({ ok: false, error: 'Немає прав!' });
const token = jwt.sign({ id: user.id, role: 'admin', isAdmin: true }, JWT_SECRET, { expiresIn: '2h' });
res.json({ ok: true, token });
} catch (err) { res.json({ ok: false, error: err.message }); }
});
app.get('/api/admin/unverified-drivers', async (req, res) => {
try {
const authHeader = req.headers['authorization'];
const token = authHeader.replace(/^Bearer\s+/, '').trim();
const decoded = jwt.verify(token, JWT_SECRET);
if (!decoded.isAdmin) return res.json({ ok: false, error: 'Ви не адмін.' });
const totalQuery = await pool.query('SELECT COUNT()::int AS count FROM device_trials');
const totalDevices = totalQuery.rows[0].count;
const todayQuery = await pool.query('SELECT COUNT()::int AS count FROM device_trials WHERE first_registered_at >= CURRENT_DATE');
const todayDevices = todayQuery.rows[0].count;
const driversResult = await pool.query(SELECT id, name, phone, car_make AS "carMake", plate_number AS "plateNumber", is_verified AS "isVerified" FROM users WHERE role = 'Водій' ORDER BY is_verified ASC, id DESC);
const passengersResult = await pool.query(SELECT id, name, phone, is_verified AS "isVerified" FROM users WHERE role = 'Пасажир' ORDER BY is_verified ASC, id DESC);
res.json({ ok: true, stats: { totalDevices, todayDevices }, drivers: driversResult.rows, passengers: passengersResult.rows });
} catch (err) { res.json({ ok: false, error: err.message }); }
});
app.post('/api/admin/verify-driver', async (req, res) => {
try {
const authHeader = req.headers['authorization'];
const token = authHeader.replace(/^Bearer\s+/, '').trim();
const decoded = jwt.verify(token, JWT_SECRET);
if (!decoded.isAdmin) return res.json({ ok: false, error: 'Заборонено' });
const { driverId, activeStatus } = req.body;
const finalStatus = activeStatus === true || activeStatus === 'true';
await pool.query('UPDATE users SET is_verified = $1 WHERE id = $2', [finalStatus, parseInt(driverId)]);
res.json({ ok: true });
} catch (err) { res.json({ ok: false, error: err.message }); }
});
app.post('/api/admin/manual-subscription', async (req, res) => {
try {
const authHeader = req.headers['authorization'];
const token = authHeader.replace(/^Bearer\s+/, '').trim();
const decoded = jwt.verify(token, JWT_SECRET);
if (!decoded.isAdmin) return res.json({ ok: false, error: 'У вас немає прав!' });
const { phone } = req.body;
const checkUser = await pool.query('SELECT id FROM users WHERE phone = $1', [phone.trim()]);
if (checkUser.rows.length === 0) return res.json({ ok: false, error: 'Не знайдено!' });
await pool.query(UPDATE users SET subscription_expires_at = '2050-01-01 00:00:00+00' WHERE phone = $1, [phone.trim()]);
res.json({ ok: true });
} catch (err) { res.json({ ok: false, error: err.message }); }
});
// ==========================================
// 💳 БЛОК ИМИТАЦИИ ОПЛАТЫ MONOBANK
// ==========================================
app.post('/api/payment/create-invoice', async (req, res) => {
try {
const authHeader = req.headers['authorization'];
const token = authHeader.replace(/^Bearer\s+/, '').trim();
const decoded = jwt.verify(token, JWT_SECRET);
const testPaymentUrl = https://onrender.com{decoded.id};
res.json({ ok: true, paymentUrl: testPaymentUrl });
} catch (err) { res.json({ ok: false, error: err.message }); }
});
app.get('/payment/simulator', (req, res) => {
const userId = req.query.userId;
let html = 'Monobank | Тестова Оплата';
html += '';
html += 'monobankТестова оплата підписки Diway150.00 ₴';
html += 'УСПІШНО СПЛАТИТИ';
html += '';
res.send(html);
});
app.post('/api/payment/webhook-simulation', express.urlencoded({ extended: true }), async (req, res) => {
try {
const { userId } = req.body;
if (!userId) return res.send('Помилка: Не вказано ID');
await pool.query(UPDATE users SET subscription_expires_at = NOW() + INTERVAL '30 days', is_verified = true WHERE id = $1, [parseInt(userId)]);
res.send('🟢 Оплата успішна!Підписку Diway активовано на 30 днів. Можете повернутися в додаток.');
} catch (err) { res.send('Помилка: ' + err.message); }
});
// 🧹 Фоновая очистка старых рейсов (5 часов)
setInterval(async () => {
try {
await pool.query("DELETE FROM active_trips WHERE created_at < NOW() - INTERVAL '5 hours'");
} catch (err) { console.error(err.message); }
}, 1000 * 60 * 60);
app.listen(PORT, () => {
console.log(🚀 Server is running smoothly on port ${PORT});
});
