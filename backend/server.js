const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const db = require('./database');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: '*', credentials: true }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(morgan('combined'));

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 200,
    message: { error: '🚫 الكثير من المحاولات، حاول بعد 15 دقيقة' }
});
app.use('/api/', limiter);

app.use(express.static(path.join(__dirname, '../public')));

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ error: '❌ غير مصرح' });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: '❌ الجلسة منتهية' });
        req.user = user;
        next();
    });
};

// Auth Routes
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await db.get('SELECT * FROM users WHERE username = ? AND status = "active"', [username]);

        if (!user) return res.status(401).json({ error: '❌ اسم المستخدم أو كلمة السر خطأ' });

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(401).json({ error: '❌ اسم المستخدم أو كلمة السر خطأ' });

        await db.run('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', [user.id]);

        const token = jwt.sign(
            { id: user.id, username: user.username, full_name: user.full_name, role: user.role, permissions: JSON.parse(user.permissions || '[]') },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_EXPIRE }
        );

        res.json({ success: true, token, user: { id: user.id, full_name: user.full_name, username: user.username, role: user.role } });
    } catch (error) {
        console.error('خطأ في تسجيل الدخول:', error);
        res.status(500).json({ error: '❌ حدث خطأ في الخادم' });
    }
});

app.get('/api/auth/me', authenticateToken, (req, res) => {
    res.json(req.user);
});

// Appointments Routes
app.get('/api/appointments', authenticateToken, async (req, res) => {
    try {
        const appointments = await db.query('SELECT * FROM appointments ORDER BY date, time');
        res.json(appointments);
    } catch (error) {
        console.error('خطأ في جلب الحجوزات:', error);
        res.status(500).json({ error: '❌ حدث خطأ في الخادم' });
    }
});

app.get('/api/appointments/public', async (req, res) => {
    try {
        const appointments = await db.query('SELECT id, client_name, date, time, status FROM appointments WHERE status = "active" ORDER BY date, time');
        res.json(appointments);
    } catch (error) {
        console.error('خطأ في جلب الحجوزات العامة:', error);
        res.status(500).json({ error: '❌ حدث خطأ في الخادم' });
    }
});

app.post('/api/appointments', async (req, res) => {
    try {
        const { client_name, client_phone, date, time } = req.body;

        const existing = await db.get('SELECT id FROM appointments WHERE date = ? AND time = ? AND status = "active"', [date, time]);
        if (existing) return res.status(400).json({ error: '❌ هذا الموعد محجوز بالفعل' });

        const result = await db.run(
            `INSERT INTO appointments (client_name, client_phone, date, time, status) VALUES (?, ?, ?, ?, 'active')`,
            [client_name, client_phone, date, time]
        );

        res.status(201).json({ success: true, message: '✅ تم حجز الموعد بنجاح', id: result.id });
    } catch (error) {
        console.error('خطأ في إنشاء الحجز:', error);
        res.status(500).json({ error: '❌ حدث خطأ في الخادم' });
    }
});

app.put('/api/appointments/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const { status } = req.body;

        await db.run(
            `UPDATE appointments SET status = ?, ${status === 'completed' ? 'completed_at = CURRENT_TIMESTAMP' : ''} WHERE id = ?`,
            [status, id]
        );

        res.json({ success: true, message: '✅ تم تحديث الحجز بنجاح' });
    } catch (error) {
        console.error('خطأ في تحديث الحجز:', error);
        res.status(500).json({ error: '❌ حدث خطأ في الخادم' });
    }
});

// Employees Routes
app.get('/api/employees', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') return res.status(403).json({ error: '❌ غير مصرح' });

        const employees = await db.query(
            `SELECT id, username, full_name, role, permissions, status, created_at, last_login FROM users WHERE username != 'admin' ORDER BY created_at DESC`
        );

        res.json(employees);
    } catch (error) {
        console.error('خطأ في جلب الموظفين:', error);
        res.status(500).json({ error: '❌ حدث خطأ في الخادم' });
    }
});

app.post('/api/employees', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') return res.status(403).json({ error: '❌ غير مصرح' });

        const { username, password, full_name, permissions } = req.body;

        const existing = await db.get('SELECT id FROM users WHERE username = ?', [username]);
        if (existing) return res.status(400).json({ error: '❌ اسم المستخدم موجود مسبقاً' });

        const salt = await bcrypt.genSalt(10);
        const hash = await bcrypt.hash(password, salt);

        const result = await db.run(
            `INSERT INTO users (username, password, full_name, role, permissions) VALUES (?, ?, ?, ?, ?)`,
            [username, hash, full_name, 'employee', JSON.stringify(permissions || [])]
        );

        res.status(201).json({ success: true, message: '✅ تم إضافة الموظف بنجاح', id: result.id });
    } catch (error) {
        console.error('خطأ في إضافة موظف:', error);
        res.status(500).json({ error: '❌ حدث خطأ في الخادم' });
    }
});

app.put('/api/employees/:id/status', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') return res.status(403).json({ error: '❌ غير مصرح' });

        const { id } = req.params;
        const { status } = req.body;

        await db.run('UPDATE users SET status = ? WHERE id = ? AND username != "admin"', [status, id]);

        res.json({ success: true, message: '✅ تم تحديث حالة الموظف' });
    } catch (error) {
        console.error('خطأ في تحديث حالة الموظف:', error);
        res.status(500).json({ error: '❌ حدث خطأ في الخادم' });
    }
});

app.delete('/api/employees/:id', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') return res.status(403).json({ error: '❌ غير مصرح' });

        const { id } = req.params;
        await db.run('DELETE FROM users WHERE id = ? AND username != "admin"', [id]);

        res.json({ success: true, message: '✅ تم حذف الموظف' });
    } catch (error) {
        console.error('خطأ في حذف الموظف:', error);
        res.status(500).json({ error: '❌ حدث خطأ في الخادم' });
    }
});

// Settings Routes
app.get('/api/settings', async (req, res) => {
    try {
        const settings = await db.query('SELECT key, value FROM settings');
        const settingsObj = {};
        settings.forEach(s => settingsObj[s.key] = s.value);
        res.json(settingsObj);
    } catch (error) {
        console.error('خطأ في جلب الإعدادات:', error);
        res.status(500).json({ error: '❌ حدث خطأ في الخادم' });
    }
});

app.put('/api/settings', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') return res.status(403).json({ error: '❌ غير مصرح' });

        const settings = req.body;
        for (let [key, value] of Object.entries(settings)) {
            await db.run('UPDATE settings SET value = ?, updated_at = CURRENT_TIMESTAMP WHERE key = ?', [value, key]);
        }

        res.json({ success: true, message: '✅ تم حفظ الإعدادات' });
    } catch (error) {
        console.error('خطأ في حفظ الإعدادات:', error);
        res.status(500).json({ error: '❌ حدث خطأ في الخادم' });
    }
});

// Stats Routes
app.get('/api/stats', authenticateToken, async (req, res) => {
    try {
        const today = new Date().toISOString().split('T')[0];

        const total = await db.get('SELECT COUNT(*) as count FROM appointments');
        const active = await db.get('SELECT COUNT(*) as count FROM appointments WHERE status = "active"');
        const completed = await db.get('SELECT COUNT(*) as count FROM appointments WHERE status = "completed"');
        const cancelled = await db.get('SELECT COUNT(*) as count FROM appointments WHERE status = "cancelled"');
        const todayCount = await db.get('SELECT COUNT(*) as count FROM appointments WHERE date = ?', [today]);

        res.json({
            total: total.count,
            active: active.count,
            completed: completed.count,
            cancelled: cancelled.count,
            today: todayCount.count
        });
    } catch (error) {
        console.error('خطأ في جلب الإحصائيات:', error);
        res.status(500).json({ error: '❌ حدث خطأ في الخادم' });
    }
});

app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '../public/index.html'));
});

app.use((err, req, res, next) => {
    console.error('❌ خطأ غير متوقع:', err);
    res.status(500).json({ error: '❌ حدث خطأ غير متوقع في الخادم' });
});

app.listen(PORT, () => {
    console.log(`
    🚀 ======================================== 🚀
    
        ✅ SalonPro System is running!
        🌐 URL: http://localhost:${PORT}
        📁 Environment: ${process.env.NODE_ENV || 'development'}
        🔑 Admin: admin / admin123
    
    🚀 ======================================== 🚀
    `);
});