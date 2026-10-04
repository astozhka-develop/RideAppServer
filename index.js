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

// 🔥 ДОБАВЛЕНО: Настройка Multer для приема изображений авто
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
    // Переводим картинку в формат Base64 для MVP хранения прямо в Supabase
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

// 🚀 Реєстрація нового користувача З ПРИВ'ЯЗКОЮ ДО ID СМАРТФОНУ (Захист від абузу триалу)
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, phone, role, password, carMake, plateNumber, deviceId } = req.body;
    if (!name || !phone || !password || !role || !deviceId) {
      return res.json({ ok: false, error: 'Заповніть обов\'язкові поля та ID пристрою!' });
    }
    
    // Проверяем, зарегистрирован ли уже этот номер телефона
    const checkUser = await pool.query('SELECT id FROM users WHERE phone = \$1', [phone]);
    if (checkUser.rows.length > 0) return res.json({ ok: false, error: 'Користувач вже зареєстрований!' });
    
    // 🔥 АНТИ-ХАКЕРСКИЙ ТРИГГЕР: Проверяем, светилось ли уже это устройство в реестре триалов
    const checkDevice = await pool.query('SELECT id FROM device_trials WHERE device_id = \$1', [deviceId]);
    if (checkDevice.rows.length === 0) {
      // Если устройство новое — бережно заносим его в реестр девайсов
      await pool.query('INSERT INTO device_trials (device_id, first_registered_at) VALUES (\$1, NOW())', [deviceId]);
    }

    const password_hash = await bcrypt.hash(password, 10);
    
    // Сохраняем пользователя, намертво привязывая к нему device_id смартфона
    const result = await pool.query(
      `INSERT INTO users (name, phone, password_hash, role, car_make, plate_number, is_verified, device_id) 
       VALUES ($1, $2, $3, $4, $5, $6, true, $7) RETURNING id`,
      [name, phone, password_hash, role, carMake || null, plateNumber || null, deviceId]
    );
    res.json({ ok: true, userId: result.rows[0].id });
  } catch (err) {
    console.error('Registration error:', err.message);
    res.json({ ok: false, error: err.message });
  }
});


// 🚀 Авторизація (Логін) — ІСПРАВЛЕНО ЧИТАННЯ ПОЛІВ ИЗ СУБД
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
    
    // 🔥 ІСПРАВЛЕНО: Читаємо змінні строго у форматі snake_case, як вони повернулися з бази Supabase!
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


// 🚀 Отримання профілю — ІСПРАВЛЕНО СОПОСТАВЛЕННЯ СТРОК З LEFT JOIN
app.get('/api/profile', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.json({ ok: false, error: 'Нет токена' });
    const token = authHeader.split(' ')[1]; 
    const decoded = jwt.verify(token, JWT_SECRET);
    
    const result = await pool.query(
      `SELECT u.id, u.name, u.phone, u.role, u.car_make, u.plate_number, 
              u.subscription_expires_at, u.device_id,
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
    
    const trialPeriodMs = 7 * 24 * 60 * 60 * 1000;
    const trialExpiryDate = new Date(deviceRegisteredAt.getTime() + trialPeriodMs);
    
    if (now < trialExpiryDate) {
      const msLeft = trialExpiryDate - now;
      daysLeft = Math.ceil(msLeft / (1000 * 60 * 60 * 24));
      isBlocked = false;
    } else {
      if (subscriptionExpiresAt && now < subscriptionExpiresAt) {
        const msLeft = subscriptionExpiresAt - now;
        daysLeft = Math.ceil(msLeft / (1000 * 60 * 60 * 24));
        isBlocked = false;
      } else {
        daysLeft = 0;
        isBlocked = true;
      }
    }
    
    // 🔥 ІСПРАВЛЕНО: Поля з LEFT JOIN переведені з snake_case у camelCase для Android Retrofit!
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


// 🚀 Оновлення даних профілю водія (ИСПРАВЛЕН ИНДЕКС ТОКЕНА)
app.put('/api/profile', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.json({ ok: false, error: 'Нет токена авторизации' });
    
    const parts = authHeader.split(' ');
    // 🔥 ИСПРАВЛЕНО: Берем именно первый индекс массива — саму JWT строку!
    const token = parts[1]; 
    
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

// 🚀 Створення активного маршруту на карті — ИСПРАВЛЕН СИНТАКСИС JS (const) И ИНДЕКС СТРОКИ
app.post('/api/trips', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.json({ ok: false, error: 'Нет токена авторизации' });
    
    const parts = authHeader.split(' ');
    const token = parts[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    
    const { role, startLat, startLon, endLat, endLon, startAddress, endAddress } = req.body;
    
    // Отменяем старые незавершенные поиски этого пользователя, чтобы не плодить дубли в базе
    await pool.query(
      "UPDATE active_trips SET status = 'cancelled' WHERE user_id = \$1 AND status = 'searching'",
      [decoded.id]
    );
    
    // 🔥 ИСПРАВЛЕНО: Котлиновский 'val' заменен на правильный JS 'const'!
    const finalStartAddress = startAddress || "Точка на карті (Старт)";
    const finalEndAddress = endAddress || "Точка на карті (Фініш)";
    
    const result = await pool.query(
      `INSERT INTO active_trips (user_id, role, start_lat, start_lon, end_lat, end_lon, start_address, end_address) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`,
      [decoded.id, role, startLat, startLon, endLat, endLon, finalStartAddress, finalEndAddress]
    );
    
    // 🔥 ИСПРАВЛЕНО: Извлекаем id строго из нулевого (первого) элемента массива строк PostgreSQL!
    res.json({ ok: true, tripId: result.rows[0].id });
    
  } catch (err) {
    console.error('Trip creation error:', err.message);
    res.json({ ok: false, error: 'Помилка сервера при створенні маршруту: ' + err.message });
  }
});

// 🚀 Поиск попутных водителей — СИНХРОНИЗАЦИЯ ТИПОВ С КЛИЕНТОМ (::int)
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
    
    // 🔥 ИСПРАВЛЕНО: Добавлено ::int к t.user_id, чтобы PostgreSQL гарантированно отдавал число, а не строку!
    const result = await pool.query(
      `SELECT t.id AS "tripId", t.user_id::int AS "driverId", t.start_lat AS "startLat", t.start_lon AS "startLon", 
              t.end_lat AS "endLat", t.end_lon AS "endLon", t.start_address AS "startAddress", t.end_address AS "endAddress",
              u.name, u.phone, u.car_make AS "carMake", u.plate_number AS "plateNumber"
       FROM active_trips t
       JOIN users u ON t.user_id = u.id
       WHERE t.role = 'driver' AND t.status = 'searching'
         AND calculate_distance($1, $2, t.start_lat, t.start_lon) <= 50.0
         AND calculate_distance($3, $4, t.end_lat, t.end_lon) <= 50.0`,
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

// 🚀 Пасажир робить ставку вибраному водію — ИСПРАВЛЕН ИНДЕКС СТРОКИ COUNT
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
    
    // 🔥 ИСПРАВЛЕНО: Извлекаем count из первой строки [0] массива результатов!
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


// 🚀 Водитель запрашивает входящие ставки для своей поездки (Исправлен синтаксис скобок!)
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

    // 🔥 ИСПРАВЛЕНО: Закрывающая скобка ) возвращена строго на место после кавычки `
    const result = await pool.query(
      `SELECT b.id AS "bidId", b.trip_id AS "passengerTripId", b.proposed_price AS "proposedPrice", 
              b.passenger_count AS "passengerCount", u.name AS "passengerName", t.start_address AS "startAddress"
       FROM ride_bids b
       JOIN users u ON b.passenger_id = u.id
       JOIN active_trips t ON b.trip_id = t.id
       WHERE b.driver_id = $1 AND b.status = 'pending'`,
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
// 🚀 Регулярный опрос статуса ставки для Пассажира (Синтаксис скобок исправлен на 100%)
app.get('/api/bids/status/passenger', async (req, res) => {
  try {
    const { tripId } = req.query;
    if (!tripId) {
      return res.json({ ok: false, error: 'Пропущений tripId' });
    }
    
    // 🔥 ИСПРАВЛЕНО: Закрывающая скобка ) возвращена на место после косой кавычки `
    const result = await pool.query(
      `SELECT b.status, u.phone AS "driverPhone"
       FROM ride_bids b
       JOIN users u ON b.driver_id = u.id
       WHERE b.trip_id = $1
       ORDER BY b.id DESC LIMIT 1`,
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
// 🖥️ БЛОК ВЕБ-ПАНЕЛИ АДМИНИСТРАТОРА (ВШИТ НАПРЯМУЮ)
// ==========================================

// Перенаправление с главной страницы на админку
app.get('/', (req, res) => {
  res.redirect('/admin');
});

// ==========================================
// 🖥️ БЛОК ВЕБ-ПАНЕЛИ АДМИНИСТРАТОРА (ВШИТ НАПРЯМУЮ)
// ==========================================
app.get('/admin', (req, res) => {
  let html = '<!DOCTYPE html><html lang="uk"><head><meta charset="UTF-8">';
  html += '<title>Панель Admin Diway</title><style>';
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
  html += '</style></head><body>';
  html += '<div class="auth-container" id="authBlock"><h2>Вхід до Diway Admin</h2>';
  html += '<div class="form-group"><label>Номер телефону</label><input type="text" id="adminPhone" placeholder="+380..."></div>';
  html += '<div class="form-group"><label>Код безпеки (2FA)</label><input type="text" id="adminCode" placeholder="777999" maxlength="6" style="text-align:center;font-weight:bold;"></div>';
  html += '<button onclick="loginAdmin()">ПІДТВЕРДИТИ ВХІД</button></div>';
  
  html += '<div class="dashboard-container" id="dashboardBlock"><h2>Панель Адміністратора Diway</h2>';
  html += '<div class="admin-section"><h3>🛠️ Ручне керування підписками </h3>';
  html += '<p style="font-size:13px; color:#666; margin-bottom:12px;">Введіть номер телефону смартфона, щоб нарахувати йому тестовий БЕЗЛІМІТ до 2050 року</p>';
  html += '<div style="display:flex; gap:10px; margin-bottom:10px;">';
  html += '<input type="text" id="targetUserPhone" placeholder="+380XXXXXXXXX" style="flex:1; height:48px;">';
  html += '<button onclick="grantManualSubscription()" style="width:200px; height:48px; background-color:#212121;">ВИДАТИ БЕЗЛІМІТ</button>';
  html += '</div></div>';

  html += '<h3>📋 Усі зареєстровані користувачі та керування доступом</h3>';
  html += '<div id="passengersList"><div class="no-data">Завантаження пасажирів...</div></div></div>';
  html += '<div id="driversList"><div class="no-data">Завантаження водіїв...</div></div></div>';
  
  html += '<script>';
  html += 'let adminToken = "";';
  html += 'async function loginAdmin() {';
  html += '  const phone = document.getElementById("adminPhone").value.trim();';
  html += '  const code = document.getElementById("adminCode").value.trim();';
  html += '  if(!phone || !code) { alert("Заповніть всі поля!"); return; }';
  html += '  try {';
  html += '    const response = await fetch("/api/admin/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ phone, code }) });';
  html += '    const data = await response.json();';
  html += '    if (data.ok) { adminToken = data.token; document.getElementById("authBlock").style.display = "none"; document.getElementById("dashboardBlock").style.display = "block"; loadUnverifiedDrivers(); }';
  html += '    else { alert("Відмовлено: " + data.error); }';
  html += '  } catch (err) { alert("Помилка мережі при вході"); }';
  html += '}';
    // 🔥 ИСПРАВЛЕНО: Полный переход на шаблонные косые кавычки ` ` убирает любые конфликты экранирования!
  html += `async function loadUnverifiedDrivers() {
    try {
      const response = await fetch("/api/admin/unverified-drivers", { headers: { "Authorization": "Bearer " + adminToken } });
      const data = await response.json();
      
      if (!data.ok) {
        document.getElementById("driversList").innerHTML = "<div class='no-data' style='color:#EF4444;'>Помилка сервера: " + data.error + "</div>";
        document.getElementById("passengersList").innerHTML = "<div class='no-data'>-</div>";
        return;
      }
      
      // ОТРИСОВКА ВОДИТЕЛЕЙ
      const listDiv = document.getElementById("driversList");
      listDiv.innerHTML = "";
      if (data.drivers && data.drivers.length > 0) {
        data.drivers.forEach(driver => {
          const card = document.createElement("div"); card.className = "driver-card";
          let statusBadge = driver.isVerified ? "<span class='badge' style='background:#D1FAE5; color:#065F46;'>Активний</span>" : "<span class='badge' style='background:#FEE2E2; color:#991B1B;'>ЗАБЛОКОВАНИЙ</span>";
          let actionButton = driver.isVerified ? "<button class='btn-approve' style='background-color:#EF4444;' onclick='toggleDriverBlock(" + driver.id + ", false)'>ЗАБЛОКУВАТИ</button>" : "<button class='btn-approve' style='background-color:#10B981;' onclick='toggleDriverBlock(" + driver.id + ", true)'>РОЗБЛОКУВАТИ</button>";
          card.innerHTML = "<div class='driver-info'><h3>" + driver.name + " " + statusBadge + "</h3><p>Тел: " + driver.phone + "</p><p><span class='badge'>" + (driver.carMake || "Авто") + " (" + (driver.plateNumber || "Б/Н") + ")</span></p></div><div class='actions'><div style='display:flex; gap:10px;'>" + actionButton + "</div></div>";
          listDiv.appendChild(card);
        });
      } else { listDiv.innerHTML = "<div class='no-data'>Водіїв не знайдено.</div>"; }
      
      // ОТРИСОВКА ПАССАЖИРОВ
      const passDiv = document.getElementById("passengersList");
      passDiv.innerHTML = "";
      if (data.passengers && data.passengers.length > 0) {
        data.passengers.forEach(pass => {
          const card = document.createElement("div"); card.className = "driver-card";
          let statusBadge = pass.isVerified ? "<span class='badge' style='background:#D1FAE5; color:#065F46;'>Активний</span>" : "<span class='badge' style='background:#FEE2E2; color:#991B1B;'>ЗАБЛОКОВАНИЙ</span>";
          let actionButton = pass.isVerified ? "<button class='btn-approve' style='background-color:#EF4444;' onclick='toggleDriverBlock(" + pass.id + ", false)'>ЗАБЛОКУВАТИ</button>" : "<button class='btn-approve' style='background-color:#10B981;' onclick='toggleDriverBlock(" + pass.id + ", true)'>РОЗБЛОКУВАТИ</button>";
          card.innerHTML = "<div class='driver-info'><h3>" + pass.name + " " + statusBadge + "</h3><p>Тел: " + pass.phone + "</p></div><div class='actions'><div style='display:flex; gap:10px;'>" + actionButton + "</div></div>";
          passDiv.appendChild(card);
        });
      } else { passDiv.innerHTML = "<div class='no-data'>Пасажирів не знайдено.</div>"; }
      
    } catch (err) { 
      document.getElementById("driversList").innerHTML = "<div class='no-data' style='color:#EF4444;'>Критична помилка: " + err.message + "</div>";
      document.getElementById("passengersList").innerHTML = "<div class='no-data'>-</div>";
    }
  };`;

  
  html += 'async function toggleDriverBlock(driverId, setActivate) {';
  html += '  let confirmAction = confirm(setActivate ? "Розблокувати цього водія?" : "🚨 Ви впевнені, що хочете ЗАБЛОКУВАТИ цього водія? Його радар буде вимкнено!");';
  html += '  if (!confirmAction) return;';
  html += '  try {';
  html += '    const response = await fetch("/api/admin/verify-driver", {';
  html += '      method: "POST",';
  html += '      headers: { "Content-Type": "application/json", "Authorization": "Bearer " + adminToken },';
  html += '      body: JSON.stringify({ driverId, activeStatus: setActivate })';
  html += '    });';
  html += '    const data = await response.json();';
  html += '    if (data.ok) { alert(setActivate ? "Водія успішно розблоковано!" : "🔴 Водія успішно заблоковано в Supabase!"); loadUnverifiedDrivers(); }';
  html += '    else { alert("Помилка: " + data.error); }';
  html += '  } catch (err) { alert("Помилка сервера"); }';
  html += '}';
  
  html += 'async function grantManualSubscription() {';
  html += '  const phone = document.getElementById("targetUserPhone").value.trim();';
  html += '  if(!phone) { alert("Введіть номер телефону!"); return; }';
  html += '  try {';
  html += '    const response = await fetch("/api/admin/manual-subscription", {';
  html += '      method: "POST",';
  html += '      headers: { "Content-Type": "application/json", "Authorization": "Bearer " + adminToken },';
  html += '      body: JSON.stringify({ phone })';
  html += '    });';
  html += '    const data = await response.json();';
  html += '    if(data.ok) { alert("🟢 Тестовий безліміт успішно активовано до 2050 року!"); document.getElementById("targetUserPhone").value = ""; }';
  html += '    else { alert("❌ Помилка: " + data.error); }';
  html += '  } catch(err) { alert("Помилка з\'єднання з сервером"); }';
  html += '}';
  
  html += '</script></body></html>';
  res.send(html);
});

// 🚀 Адмін логін на сторінці — ІСПРАВЛЕНО ЧИТАННЯ ФЛАГА is_admin
app.post('/api/admin/login', async (req, res) => {
  try {
    const { phone, code } = req.body;
    if (code !== '777999') return res.json({ ok: false, error: 'Невірний 2FA код!' });
    const result = await pool.query('SELECT * FROM users WHERE phone = \$1', [phone]);
    if (result.rows.length === 0) return res.json({ ok: false, error: 'Користувача не знайдено' });
    
    const user = result.rows[0];
    
    // 🔥 ІСПРАВЛЕНО: Читаємо прапорець адміна строго з підкресленням із бази даних!
    if (!user.is_admin) {
      return res.json({ ok: false, error: 'У вас немає прав адміністратора!' });
    }

    const token = jwt.sign({ id: user.id, role: 'admin', isAdmin: true }, JWT_SECRET, { expiresIn: '2h' });
    res.json({ ok: true, token });
  } catch (err) { res.json({ ok: false, error: err.message }); }
});

// 🚀 АДМІН: Отримання ПОВНОГО списку водіїв та пасажирів (ВСЕЯДНИЙ ДЛЯ ВЕБ І АНДРОЇД)
app.get('/api/admin/unverified-drivers', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.json({ ok: false, error: 'Немає токена авторизації' });
    
    const parts = authHeader.split(' ');
    
    // 🔥 ИСПРАВЛЕНО: Еслиparts[1] существует (это веб-браузер с Bearer), берем его. Если нет (это Android) — берем чистый parts[0]!
    const token = parts.length > 1 ? parts[1] : parts[0];
    
    const decoded = jwt.verify(token, JWT_SECRET);
    if (!decoded.isAdmin) return res.json({ ok: false, error: 'Ви не адмін.' });
    
    // 1. Витягуємо ВСІХ водіїв з бази
    const driversResult = await pool.query(`
      SELECT id, name, phone, car_make AS "carMake", plate_number AS "plateNumber", is_verified AS "isVerified"
      FROM users 
      WHERE role = 'Водій' 
      ORDER BY is_verified ASC, id DESC
    `);

    // 2. Витягуємо ВСІХ пасажирів з бази
    const passengersResult = await pool.query(`
      SELECT id, name, phone, is_verified AS "isVerified"
      FROM users 
      WHERE role = 'Пасажир' 
      ORDER BY is_verified ASC, id DESC
    `);

    // Віддаємо на веб-сторінку обидва масиви даних
    res.json({ 
      ok: true, 
      drivers: driversResult.rows,
      passengers: passengersResult.rows
    });
  } catch (err) { 
    console.error('Admin drivers fetch error:', err.message);
    res.json({ ok: false, error: 'Помилка безпеки токена: ' + err.message }); 
  }
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

// 🚀 АДМІН: Ручне нарахування безлімітного доступу тестовим смартфонам по номеру телефону
app.post('/api/admin/manual-subscription', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.json({ ok: false, error: 'Немає токена авторизації' });
    
    const parts = authHeader.split(' ');
    const token = parts[1];
    const decoded = jwt.verify(token, JWT_SECRET);

    // Перевіряємо права адміністратора
    if (!decoded.isAdmin) {
      return res.json({ ok: false, error: 'У вас немає прав доступу!' });
    }

    const { phone } = req.body;
    if (!phone) return res.json({ ok: false, error: 'Введіть номер телефону користувача!' });

    // Проверяем, существует ли пользователь с таким номером
    const checkUser = await pool.query('SELECT id FROM users WHERE phone = \$1', [phone.trim()]);
    if (checkUser.rows.length === 0) {
      return res.json({ ok: false, error: 'Користувача з таким номером телефону не знайдено!' });
    }

    // 🔥 НАЧИСЛЯЕМ БЕЗЛИМИТ: Принудительно сдвигаем подписку до 2050 года для тестов
    await pool.query(
      `UPDATE users 
       SET subscription_expires_at = '2050-01-01 00:00:00+00' 
       WHERE phone = $1`,
      [phone.trim()]
    );

    res.json({ ok: true });
  } catch (err) {
    console.error('Admin manual subscription error:', err.message);
    res.json({ ok: false, error: 'Помилка сервера: ' + err.message });
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
    // 🔥 ИСПРАВЛЕНО: Безопасное извлечение токена независимо от формата (Bearer или чистый)
    const token = parts.length > 1 ? parts[1] : parts[0];
    const decoded = jwt.verify(token, JWT_SECRET);
    
    const testPaymentUrl = `https://diway.onrender.com/payment/simulator?userId=${decoded.id}`;
    res.json({ ok: true, paymentUrl: testPaymentUrl });
  } catch (err) {
    console.error('Invoice creation error:', err.message);
    res.json({ ok: false, error: 'Помилка платежу: ' + err.message });
  }
});


// 🚀 2. Веб-страница симулятора оплаты Monobank (Mono Pay)
app.get('/payment/simulator', (req, res) => {
  const userId = req.query.userId;
  let html = '<!DOCTYPE html><html lang="uk"><head><meta charset="UTF-8">';
  html += '<title>Monobank | Тестова Оплата</title><style>';
  html += 'body{font-family:sans-serif;background-color:#FFF;margin:0;padding:20px;display:flex;justify-content:center;align-items:center;min-height:100vh;}';
  html += '.card{max-width:400px;width:100%;border:2px solid #E0E0E0;padding:30px;border-radius:20px;text-align:center;box-shadow:0 8px 24px rgba(0,0,0,0.05);}';
  html += 'h2{color:#FF1744;margin-bottom:10px;}';
  html += '.price{font-size:32px;font-weight:bold;margin:20px 0;color:#212121;}';
  html += 'button{width:100%;height:54px;background-color:#212121;color:#fff;border:none;border-radius:12px;font-size:16px;font-weight:bold;cursor:pointer;}';
  html += '</style></head><body>';
  html += '<div class="card"><h2>monobank | fono pay</h2><p>Тестова оплата підписки Diway</p>';
  html += '<div class="price">150.00 ₴</div>';
  html += '<form action="/api/payment/webhook-simulation" method="POST">';
  html += '<input type="hidden" name="userId" value="' + userId + '">';
  html += '<button type="submit">УСПІШНО СПЛАТИТИ 150 ГРН</button></form></div>';
  html += '</body></html>';
  res.send(html);
});

// 🚀 3. Симуляция Вебхука Monobank: Принимает успешную оплату и сдвигает подписку на 30 дней в Supabase
app.post('/api/payment/webhook-simulation', express.urlencoded({ extended: true }), async (req, res) => {
  try {
    const { userId } = req.body;
    if (!userId) return res.send('Помилка: Не вказано ID користувача');

    // Сдвигаем подписку вперед на 30 дней от текущего момента NOW()
    await pool.query(
      `UPDATE users 
       SET subscription_expires_at = NOW() + INTERVAL '30 days' 
       WHERE id = $1`,
      [parseInt(userId)]
    );

    res.send('<!DOCTYPE html><html lang="uk"><body style="font-family:sans-serif;text-align:center;padding-top:50px;"><h1 style="color:#10B981;">🟢 Оплата успішна!</h1><p>Підписку Diway активовано на 30 днів. Можете повернутися в додаток.</p></body></html>');
  } catch (err) {
    res.send('Помилка обробки платежу: ' + err.message);
  }
});


// ==========================================
// 🚀 ЗАПУСКАЕМ СЕРВЕР (КАВЫЧКИ ИСПРАВЛЕНЫ!)
// ==========================================
app.listen(PORT, () => {
  console.log(`🚀 Server is running smoothly on port ${PORT}`);
});

