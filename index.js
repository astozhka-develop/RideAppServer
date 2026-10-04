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
  limits: { fileSize: 5 * 1024 * 1024 }, // Лимит: 5 Мб на одну фотографию
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

// 🚀 Реєстрація нового користувача З ПРИВ'ЯЗКОЮ ДО ID СМАРТФОНУ
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, phone, role, password, carMake, plateNumber, deviceId } = req.body;
    if (!name || !phone || !password || !role || !deviceId) {
      return res.json({ ok: false, error: 'Заповніть обов\'язкові поля та ID пристрою!' });
    }
    
    const checkUser = await pool.query('SELECT id FROM users WHERE phone = $1', [phone]);
    if (checkUser.rows.length > 0) return res.json({ ok: false, error: 'Користувач вже зареєстрований!' });
    
    const checkDevice = await pool.query('SELECT id FROM device_trials WHERE device_id = $1', [deviceId]);
    if (checkDevice.rows.length === 0) {
      await pool.query('INSERT INTO device_trials (device_id, first_registered_at) VALUES ($1, NOW())', [deviceId]);
    }
    const password_hash = await bcrypt.hash(password, 10);
    
    const result = await pool.query(
      `INSERT INTO users (name, phone, password_hash, role, car_make, plate_number, is_verified, device_id, created_at) 
       VALUES ($1, $2, $3, $4, $5, $6, true, $7, NOW()) RETURNING id`,
      [name, phone, password_hash, role, carMake || null, plateNumber || null, deviceId]
    );
    res.json({ ok: true, userId: result.rows[0].id });
  } catch (err) {
    console.error('Registration error:', err.message);
    res.json({ ok: false, error: err.message });
  }
});

// 🚀 Авторизація (Логін)
app.post('/api/auth/login', async (req, res) => {
  try {
    const { phone, password } = req.body;
    if (!phone || !password) return res.json({ ok: false, error: 'Заповніть всі поля!' });
    
    const result = await pool.query('SELECT * FROM users WHERE phone = $1', [phone]);
    if (result.rows.length === 0) return res.json({ ok: false, error: 'Користувача не знайдено' });
    
    const user = result.rows[0]; 
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.json({ ok: false, error: 'Невірний пароль' });
    
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

// 🚀 Отримання профілю
app.get('/api/profile', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.json({ ok: false, error: 'Нет токена' });
    const token = authHeader.split(' ')[1]; 
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
    const deviceRegisteredAt = user.first_registered_at ? new Date(user.first_registered_at) : now;
    const subscriptionExpiresAt = user.subscription_expires_at ? new Date(user.subscription_expires_at) : null;
    
    let daysLeft = 0;
    let isBlocked = false;
    
    const trialPeriodMs = 7 * 24 * 60 * 60 * 1000;
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
        id: user.id, name: user.name, phone: user.phone, role: user.role,
        carMake: user.car_make, plateNumber: user.plate_number, 
        daysLeft: daysLeft, isBlocked: isBlocked
      }
    });
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
    const token = authHeader.split(' ')[1]; 
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

// 🚀 Створення активного маршруту на карті
app.post('/api/trips', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.json({ ok: false, error: 'Нет токена авторизации' });
    
    const parts = authHeader.split(' ');
    const token = parts.length > 1 ? parts[1] : parts[0];
    const decoded = jwt.verify(token, JWT_SECRET);
    
    const checkUserStatus = await pool.query('SELECT is_verified FROM users WHERE id = $1', [decoded.id]);
    if (checkUserStatus.rows.length === 0 || checkUserStatus.rows[0].is_verified === false) {
      return res.json({ ok: false, error: 'Доступ обмежено! Ваш аккаунт заблоковано адміністрацією.' });
    }
    
    const { role, startLat, startLon, endLat, endLon, startAddress, endAddress } = req.body;
    
    await pool.query(
      "UPDATE active_trips SET status = 'cancelled' WHERE user_id = $1 AND status = 'searching'",
      [decoded.id]
    );
    
    const finalStartAddress = startAddress || "Точка на карті (Старт)";
    const finalEndAddress = endAddress || "Точка на карті (Фініш)";
    
    const result = await pool.query(
      `INSERT INTO active_trips (user_id, role, start_lat, start_lon, end_lat, end_lon, start_address, end_address) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`,
      [decoded.id, role, startLat, startLon, endLat, endLon, finalStartAddress, finalEndAddress]
    );
    
    res.json({ ok: true, tripId: result.rows[0].id });
  } catch (err) {
    console.error('Trip creation error:', err.message);
    res.json({ ok: false, error: 'Помилка сервера при створенні маршруту: ' + err.message });
  }
});

// 🚀 Пошук попутних водіїв для пасажира
app.get('/api/trips/drivers', async (req, res) => {
  try {
    const { startLat, startLon, endLat, endLon } = req.query;
    if (!startLat || !startLon || !endLat || !endLon) {
        return res.json({ ok: false, error: 'Пропущені координати пасажира' });
    }
    const result = await pool.query(
      `SELECT t.id AS "tripId", t.user_id::int AS "driverId", t.start_lat AS "startLat", t.start_lon AS "startLon", 
              t.end_lat AS "endLat", t.end_lon AS "endLon", t.start_address AS "startAddress", t.end_address AS "endAddress",
              u.name, u.phone, u.car_make AS "carMake", u.plate_number AS "plateNumber"
       FROM active_trips t
       JOIN users u ON t.user_id = u.id
       WHERE t.role = 'driver' AND t.status = 'searching' AND u.is_verified = true
       ORDER BY t.id DESC`
    );
    res.json({ ok: true, drivers: result.rows });
  } catch (err) {
    console.error('Get drivers error:', err.message);
    res.json({ ok: false, error: 'Помилка сервера пошуку водіїв: ' + err.message });
  }
});

// 🚀 БЛОК СТАВОК (ТОРГИ) — СИНТАКСИС КОСЫХ КАВЫЧЕК ПОЛНОСТЬЮ ИСПРАВЛЕН
app.post('/api/bids', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.json({ ok: false, error: 'Нет токена авторизации' });
    const parts = authHeader.split(' ');
    const token = parts.length > 1 ? parts[1] : parts[0];
    const decoded = jwt.verify(token, JWT_SECRET);
    const { tripId, driverId, proposedPrice, passengerCount } = req.body;
    
    // 🔥 ИСПРАВЛЕНО: Запрос обернут в строгие косые кавычки ` `, баланс скобок идеален!
    const checkAttempts = await pool.query(
      `SELECT COUNT(*)::int AS count FROM ride_bids WHERE trip_id = $1 AND passenger_id = $2 AND driver_id = $3`,
      [tripId, decoded.id, driverId]
    );
    
    const currentAttempts = checkAttempts.rows[0].count;
    const checkDriverStatus = await pool.query('SELECT is_verified FROM users WHERE id = \$1', [driverId]);
    if (checkDriverStatus.rows.length === 0 || !checkDriverStatus.rows[0].is_verified) {
      return res.json({ ok: false, error: 'Доступ обмежено! Цей водій заблокований адміністрацією Diway.' });
    }
    if (currentAttempts >= 3) return res.json({ ok: false, error: 'Ви вичерпали ліміт ставок (макс. 3) для цього водія!' });
    
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

app.get('/api/bids/driver/incoming', async (req, res) => {
try {
const authHeader = req.headers['authorization'];
if (!authHeader) return res.json({ ok: false, error: 'Немає токена авторизації' });
const token = authHeader.split(' ')[1];
const decoded = jwt.verify(token, JWT_SECRET);
const { tripId } = req.query;
if (!tripId) return res.json({ ok: false, error: 'Пропущений tripId водія' });
const result = await pool.query(
SELECT b.id AS "bidId", b.trip_id AS "passengerTripId", b.proposed_price AS "proposedPrice", b.passenger_count AS "passengerCount", u.name AS "passengerName", t.start_address AS "startAddress" FROM ride_bids b JOIN users u ON b.passenger_id = u.id JOIN active_trips t ON b.trip_id = t.id WHERE b.driver_id = $1 AND b.status = 'pending',
[decoded.id]
);
res.json({ ok: true, bids: result.rows });
} catch (err) {
res.json({ ok: false, error: err.message });
}
});
app.post('/api/bids/respond', async (req, res) => {
try {
const { bidId, status } = req.body;
await pool.query("UPDATE ride_bids SET status = $1 WHERE id = $2", [status, bidId]);
res.json({ ok: true });
} catch (err) {
res.json({ ok: false, error: err.message });
}
});
app.get('/api/bids/status/passenger', async (req, res) => {
try {
const { tripId } = req.query;
const result = await pool.query(
SELECT b.status, u.phone AS "driverPhone" FROM ride_bids b JOIN users u ON b.driver_id = u.id WHERE b.trip_id = $1 ORDER BY b.id DESC LIMIT 1,
[tripId]
);
if (result.rows.length === 0) return res.json({ ok: true, status: 'pending', driverPhone: null });
// 🔥 ИСПРАВЛЕНО СИНТАКСИС: Извлечение значений переведено на нулевой индекс массива результатов
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
// 🖥️ БЛОК ВЕБ-ПАНЕЛИ АДМИНИСТРАТОРА
// ==========================================
app.get('/', (req, res) => {
res.redirect('/admin');
});
app.get('/admin', (req, res) => {
let html = '';
html += 'Панель Admin Diway';
html += 'body{font-family:sans-serif;background-color:#F4F6F9;margin:0;padding:0;color:#212121;}';
html += '.auth-container,.dashboard-container{max-width:500px;margin:40px auto;background:#FFFFFF;padding:40px;border-radius:24px;box-shadow:0 10px 30px rgba(0,0,0,0.05);}';
html += '.dashboard-container{max-width:850px;margin:20px auto;display:none;}';
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
// Плитки аналитики
html += '.stats-row{display:flex; gap:20px; margin-bottom:24px;}';
html += '.stats-card{flex:1; background:#0D47A1; color:#FFF; padding:24px; border-radius:16px; text-align:center; box-shadow:0 8px 20px rgba(13,71,161,0.15);}';
html += '.stats-card.today{background:#10B981; box-shadow:0 8px 20px rgba(16,185,129,0.15);}';
html += '.stats-number{font-size:36px; font-weight:bold; margin-top:8px;}';
html += '';
html += 'Вхід до Diway Admin';
html += 'Номер телефону';
html += 'Код безпеки (2FA)';
html += 'ПІДТВЕРДИТИ ВХІД';
html += 'Панель Адміністратора Diway';
// Плитки аналитики в верстке
html += '';
html += ' 📊 ВСЬОГО КОРИСТУВАЧІВ...';
html += ' 📈 РЕЄСТРАЦІЇ ЗА СЬОГОДНІ...';
html += '';
html += '🛠️ Ручне керування підписками';
html += 'Введіть номер телефону смартфона, щоб нарахувати йому тестовий БЕЗЛІМІТ до 2050 року';
html += '';
html += '';
html += 'ВИДАТИ БЕЗЛІМІТ';
html += '';
html += '📋 Усі зареєстровані водії';
html += 'Завантаження водіїв...';
html += '👥 Усі зареєстровані пасажири';
html += 'Завантаження пасажирів...';
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
if (!data.ok) {
document.getElementById("driversList").innerHTML = "Помилка сервера: " + data.error + "";
document.getElementById("passengersList").innerHTML = "-";
return;
}
if (data.stats) {
document.getElementById("statTotalUsers").innerText = data.stats.totalUsers;
document.getElementById("statTodayUsers").innerText = data.stats.todayUsers;
}
const listDiv = document.getElementById("driversList");
listDiv.innerHTML = "";
if (data.drivers && data.drivers.length > 0) {
data.drivers.forEach(driver => {
const card = document.createElement("div"); card.className = "driver-card";
let isDriverActive = driver.isVerified === true || driver.isVerified === 'true' || driver.isVerified === 1;
let statusBadge = isDriverActive ? "Активний" : "ЗАБЛОКОВАНИЙ";
let actionButton = isDriverActive ? "ЗАБЛОКУВАТИ" : "РОЗБЛОКУВАТИ";
let payStatus = driver.payBlocked ? "[Тріал закінчився / Екран заблоковано]" : "[Доступ активний. Залишилось: " + driver.daysLeft + " дн.]";
card.innerHTML = "" + driver.name + " " + statusBadge + payStatus + "Тел: " + driver.phone + "" + (driver.carMake || "Авто") + " (" + (driver.plateNumber || "Б/Н") + ")" + actionButton + "";
listDiv.appendChild(card);
});
} else { listDiv.innerHTML = "Водіїв не знайдено."; }
const passDiv = document.getElementById("passengersList");
passDiv.innerHTML = "";
if (data.passengers && data.passengers.length > 0) {
data.passengers.forEach(pass => {
const card = document.createElement("div"); card.className = "driver-card";
let isPassengerActive = pass.isVerified === true || pass.isVerified === 'true' || pass.isVerified === 1;
let statusBadge = isPassengerActive ? "Активний" : "ЗАБЛОКОВАНИЙ";
let actionButton = isPassengerActive ? "ЗАБЛОКУВАТИ" : "РОЗБЛОКУВАТИ";
let payStatus = pass.payBlocked ? "[Тріал закінчився / Екран заблоковано]" : "[Доступ активний. Залишилось: " + pass.daysLeft + " дн.]";
card.innerHTML = "" + pass.name + " " + statusBadge + payStatus + "Тел: " + pass.phone + "" + actionButton + "";
passDiv.appendChild(card);
});
} else { passDiv.innerHTML = "Пасажирів не знайдено."; }
} catch (err) {
document.getElementById("driversList").innerHTML = "Критична помилка: " + err.message;
}
};`;
html += 'async function toggleDriverBlock(driverId, setActivate) {';
html += ' let confirmAction = confirm(setActivate ? "Розблокувати цього користувача?" : "🚨 Ви впевнені, що хочете ЗАБЛОКУВАТИ користувача? Доступ до додатку перекриється!");';
html += ' if (!confirmAction) return;';
html += ' try {';
html += ' const response = await fetch("/api/admin/verify-driver", {';
html += ' method: "POST",';
html += ' headers: { "Content-Type": "application/json", "Authorization": "Bearer " + adminToken },';
html += ' body: JSON.stringify({ driverId, activeStatus: setActivate })';
html += ' });';
html += ' const data = await response.json();';
html += ' if (data.ok) { alert("Статус доступу успішно змінено в Supabase!"); loadUnverifiedDrivers(); }';
html += ' else { alert("Помилка: " + data.error); }';
html += ' } catch (err) { alert("Помилка сервера"); }';
html += '}';
html += 'async function grantManualSubscription() {';
html += ' const phone = document.getElementById("targetUserPhone").value.trim();';
html += ' if(!phone) { alert("Введіть номер телефону!"); return; }';
html += ' try {';
html += ' const response = await fetch("/api/admin/manual-subscription", {';
html += ' method: "POST",';
html += ' headers: { "Content-Type": "application/json", "Authorization": "Bearer " + adminToken },';
html += ' body: JSON.stringify({ phone })';
html += ' });';
html += ' const data = await response.json();';
html += ' if(data.ok) { alert("🟢 Тестовий безліміт успішно активовано до 2050 року!"); document.getElementById("targetUserPhone").value = ""; loadUnverifiedDrivers(); }';
html += ' else { alert("❌ Помилка: " + data.error); }';
html += ' } catch(err) { alert("Помилка з'єднання з сервером"); }';
html += '}';
html += '';
res.send(html);
});
// 🚀 Роут логіну адміністратора (ИСПРАВЛЕН ИНДЕКС СТРОКИ)
app.post('/api/admin/login', async (req, res) => {
try {
const { phone, code } = req.body;
if (!phone || !code) return res.json({ ok: false, error: 'Заповніть всі поля!' });
if (code !== '777999') return res.json({ ok: false, error: 'Невірний 2FA код безпеки!' });
const result = await pool.query('SELECT * FROM users WHERE phone = $1', [phone.trim()]);
if (result.rows.length === 0) {
return res.json({ ok: false, error: 'Користувача з таким номером не знайдено в базі!' });
}
// 🔥 ИСПРАВЛЕНО: Достаем именно первый индекс [0] строки из базы!
const user = result.rows[0];
if (!user.is_admin) {
return res.json({ ok: false, error: 'Доступ заблоковано! Ваш номер не має прав адміністратора.' });
}
const token = jwt.sign(
{ id: user.id, role: 'admin', isAdmin: true },
JWT_SECRET,
{ expiresIn: '2h' }
);
res.json({ ok: true, token });
} catch (err) {
console.error('Admin login error:', err.message);
res.json({ ok: false, error: 'Помилка сервера: ' + err.message });
}
});
// 🚀 АДМІН: Отримання ПОВНОГО списку водіїв, пасажирів та метрик аналітики
app.get('/api/admin/unverified-drivers', async (req, res) => {
try {
const authHeader = req.headers['authorization'];
if (!authHeader) return res.json({ ok: false, error: 'Немає токена авторизації' });
const parts = authHeader.split(' ');
const token = parts.length > 1 ? parts[1] : parts[0];
const decoded = jwt.verify(token, JWT_SECRET);
if (!decoded.isAdmin) return res.json({ ok: false, error: 'Ви не адмін.' });
// 🔥 ИСПРАВЛЕНО: Чтение .rows[0].count приведено к строгим стандартам PostgreSQL
const totalUsersQuery = await pool.query("SELECT COUNT(*)::int AS count FROM users");
const totalUsers = totalUsersQuery.rows[0].count;
const todayUsersQuery = await pool.query(
"SELECT COUNT(*)::int AS count FROM users WHERE created_at >= CURRENT_DATE"
);
const todayUsers = todayUsersQuery.rows[0].count;
const driversResult = await pool.query(SELECT u.id, u.name, u.phone, u.car_make AS "carMake", u.plate_number AS "plateNumber", u.is_verified AS "isVerified", u.subscription_expires_at AS "subExpires", d.first_registered_at AS "deviceReg" FROM users u LEFT JOIN device_trials d ON u.device_id = d.device_id WHERE u.role = 'Водій' ORDER BY u.is_verified ASC, u.id DESC);
const passengersResult = await pool.query(SELECT u.id, u.name, u.phone, u.is_verified AS "isVerified", u.subscription_expires_at AS "subExpires", d.first_registered_at AS "deviceReg" FROM users u LEFT JOIN device_trials d ON u.device_id = d.device_id WHERE u.role = 'Пасажир' ORDER BY u.is_verified ASC, u.id DESC);
const now = new Date();
const formatUser = (row) => {
const deviceRegisteredAt = row.deviceReg ? new Date(row.deviceReg) : now;
const subscriptionExpiresAt = row.subExpires ? new Date(row.subExpires) : null;
let daysLeft = 0;
let payBlocked = false;
const trialPeriodMs = 7 * 24 * 60 * 60 * 1000;
const trialExpiryDate = new Date(deviceRegisteredAt.getTime() + trialPeriodMs);
if (subscriptionExpiresAt && now < subscriptionExpiresAt) {
daysLeft = Math.ceil((subscriptionExpiresAt - now) / (1000 * 60 * 60 * 24));
payBlocked = false;
} else if (now < trialExpiryDate) {
daysLeft = Math.ceil((trialExpiryDate - now) / (1000 * 60 * 60 * 24));
payBlocked = false;
} else {
daysLeft = 0;
payBlocked = true;
}
return {
id: row.id, name: row.name, phone: row.phone, carMake: row.carMake, plateNumber: row.plateNumber,
isVerified: row.isVerified, daysLeft, payBlocked
};
};
res.json({
ok: true,
stats: { totalUsers, todayUsers },
drivers: driversResult.rows.map(formatUser),
passengers: passengersResult.rows.map(formatUser)
});
} catch (err) {
console.error('Admin metrics fetch error:', err.message);
res.json({ ok: false, error: err.message });
}
});
// 🚀 АДМІН: Переключення статусу блокування користувача
app.post('/api/admin/verify-driver', async (req, res) => {
try {
const authHeader = req.headers['authorization'];
if (!authHeader) return res.json({ ok: false, error: 'Немає токена авторизації' });
const parts = authHeader.split(' ');
const token = parts.length > 1 ? parts[1] : parts[0];
const decoded = jwt.verify(token, JWT_SECRET);
if (!decoded.isAdmin) return res.json({ ok: false, error: 'Заборонено' });
const { driverId, activeStatus } = req.body;
const finalStatus = activeStatus === true || activeStatus === 'true';
await pool.query('UPDATE users SET is_verified = $1 WHERE id = $2', [finalStatus, parseInt(driverId)]);
res.json({ ok: true });
} catch (err) {
res.json({ ok: false, error: err.message });
}
});
// 🚀 АДМІН: Ручне нарахування безлімітного доступу тестовим смартфонам
app.post('/api/admin/manual-subscription', async (req, res) => {
try {
const authHeader = req.headers['authorization'];
if (!authHeader) return res.json({ ok: false, error: 'Немає токена авторизації' });
const parts = authHeader.split(' ');
const token = parts.length > 1 ? parts[1] : parts[0];
const decoded = jwt.verify(token, JWT_SECRET);
if (!decoded.isAdmin) return res.json({ ok: false, error: 'У вас немає прав доступу!' });
const { phone } = req.body;
if (!phone) return res.json({ ok: false, error: 'Введіть номер телефону користувача!' });
const checkUser = await pool.query('SELECT id FROM users WHERE phone = $1', [phone.trim()]);
if (checkUser.rows.length === 0) return res.json({ ok: false, error: 'Користувача з таким номером телефону не знайдено!' });
await pool.query("UPDATE users SET subscription_expires_at = '2050-01-01 00:00:00+00' WHERE phone = $1", [phone.trim()]);
res.json({ ok: true });
} catch (err) {
res.json({ ok: false, error: err.message });
}
});
// ==========================================
// 💳 БЛОК ИМИТАЦИИ ОПЛАТЫ MONOBANK (MONO PAY)
// ==========================================
app.post('/api/payment/create-invoice', async (req, res) => {
try {
const authHeader = req.headers['authorization'];
if (!authHeader) return res.json({ ok: false, error: 'Нет токена авторизации' });
const parts = authHeader.split(' ');
const token = parts.length > 1 ? parts[1] : parts[0];
const decoded = jwt.verify(token, JWT_SECRET);
const testPaymentUrl = https://onrender.com{decoded.id};
res.json({ ok: true, paymentUrl: testPaymentUrl });
} catch (err) {
res.json({ ok: false, error: 'Помилка платежу: ' + err.message });
}
});
app.get('/payment/simulator', (req, res) => {
const userId = req.query.userId;
let html = '';
html += 'Monobank | Тестова Оплата';
html += 'body{font-family:sans-serif;background-color:#FFF;margin:0;padding:20px;display:flex;justify-content:center;align-items:center;min-height:100vh;}';
html += '.card{max-width:400px;width:100%;border:2px solid #E0E0E0;padding:30px;border-radius:20px;text-align:center;box-shadow:0 8px 24px rgba(0,0,0,0.05);}';
html += 'h2{color:#FF1744;margin-bottom:10px;}';
html += '.price{font-size:32px;font-weight:bold;margin:20px 0;color:#212121;}';
html += 'button{width:100%;height:54px;background-color:#212121;color:#fff;border:none;border-radius:12px;font-size:16px;font-weight:bold;cursor:pointer;}';
html += '';
html += 'monobank | fono payТестова оплата підписки Diway';
html += '150.00 ₴';
html += '';
html += '';
html += 'УСПІШНО СПЛАТИТИ 150 ГРН';
html += '';
res.send(html);
});
app.post('/api/payment/webhook-simulation', express.urlencoded({ extended: true }), async (req, res) => {
try {
const { userId } = req.body;
if (!userId) return res.send('Помилка: Не вказано ID користувача');
await pool.query(
UPDATE users SET subscription_expires_at = NOW() + INTERVAL '30 days' WHERE id = $1,
[parseInt(userId)]
);
res.send('🟢 Оплата успішна!Підписку Diway активовано на 30 днів. Можете повернутися в додаток.');
} catch (err) {
res.send('Помилка обробки платежу: ' + err.message);
}
});
