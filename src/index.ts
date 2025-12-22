import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import { Pool } from 'pg';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import multer from 'multer';
import * as path from 'path'; // Исправлен импорт для сборки
import * as fs from 'fs';     // Исправлен импорт для сборки
import * as crypto from 'crypto'; // Исправлен импорт для сборки

dotenv.config();

// --- CONFIG ---
const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'secret';
const UPLOAD_DIR = process.env.UPLOAD_DIR || '/app/uploads';

// Подключение к БД
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

// Настройка хранилища файлов (Multer)
if (!fs.existsSync(UPLOAD_DIR)) {
    fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, UPLOAD_DIR);
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + path.extname(file.originalname));
    }
});
const upload = multer({ storage: storage });

app.use(cors());
app.use(express.json());

// --- MIDDLEWARE ---
interface AuthRequest extends Request {
    user?: any;
}

const authenticateToken = async (req: AuthRequest, res: Response, next: NextFunction) => {
  const apiKey = req.headers['x-api-key'] as string;
  
  // 1. Проверка API Key (для n8n)
  if (apiKey) {
    try {
      const result = await pool.query('SELECT id FROM tenants WHERE api_key = $1', [apiKey]);
      if (result.rows.length > 0) {
        // Роль 'system' означает, что запрос пришел от автоматики (n8n)
        req.user = { id: 0, role: 'system', tenant_id: result.rows[0].id };
        return next();
      }
    } catch (e) { console.error(e); }
  }

  // 2. Проверка Bearer Token (для веб-фронтенда)
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, (err: any, user: any) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// --- ROUTES ---

// 1. UPLOAD FILE
app.post('/api/upload', authenticateToken, upload.single('file'), (req: any, res: Response) => {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
    const fileUrl = `/uploads/${req.file.filename}`;
    res.json({ url: fileUrl });
});

// 2. AUTH & USERS
app.post('/api/auth/login', async (req: Request, res: Response) => {
  const { login, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM public.users WHERE login = $1', [login]);
    if (result.rows.length === 0) return res.status(401).json({ error: 'User not found' });

    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password, user.password_hash);
    
    if (!validPassword) return res.status(401).json({ error: 'Invalid password' });

    const token = jwt.sign({ id: user.id, role: user.role, tenant_id: user.tenant_id }, JWT_SECRET, { expiresIn: '12h' });
    res.json({ token, user: { id: user.id, full_name: user.full_name, role: user.role } });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/users', authenticateToken, async (req: AuthRequest, res: Response) => {
    if (req.user.role !== 'admin' && req.user.role !== 'system') return res.status(403).json({ error: 'Access denied' });
    const { full_name, login, password, role } = req.body;
    try {
        const hash = await bcrypt.hash(password, 10);
        const result = await pool.query(
            "INSERT INTO users (full_name, login, password_hash, role, tenant_id, is_active) VALUES ($1, $2, $3, $4, $5, true) RETURNING id, full_name",
            [full_name, login, hash, role || 'driver', req.user.tenant_id]
        );
        res.json(result.rows[0]);
    } catch (err: any) { 
        console.error('Create User Error:', err.message);
        // Обработка дубликата логина
        if (err.code === '23505') {
            return res.status(409).json({ error: 'Пользователь с таким логином уже существует' });
        }
        res.status(500).send('Error creating user'); 
    }
});

// Новое: Сохранение ID сообщения меню (для чистого чата)
app.post('/api/users/set-menu-id', authenticateToken, async (req: AuthRequest, res: Response) => {
    const { message_id } = req.body;
    let userId = req.user.id;
    if (req.user.role === 'system') userId = req.body.user_id;

    if (!userId || !message_id) return res.status(400).json({ error: 'Missing data' });

    try {
        await pool.query('UPDATE users SET last_menu_message_id = $1 WHERE id = $2', [message_id, userId]);
        res.json({ success: true });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Database error' });
    }
});

// 3. READ DATA & DICTIONARIES
app.get('/api/dashboard/stats', authenticateToken, async (req: AuthRequest, res: Response) => {
    try {
        const tId = req.user.tenant_id;
        const shifts = await pool.query("SELECT COUNT(*) FROM shifts WHERE tenant_id = $1 AND status = 'active'", [tId]);
        const drivers = await pool.query("SELECT COUNT(*) FROM users WHERE tenant_id = $1 AND role = 'driver' AND is_active = true", [tId]);
        res.json({ activeShifts: parseInt(shifts.rows[0].count), activeDrivers: parseInt(drivers.rows[0].count) });
    } catch (err) { res.status(500).send('Error'); }
});

app.get('/api/shifts', authenticateToken, async (req: AuthRequest, res: Response) => {
    try {
        // Добавили truck_plate для истории
        const sql = `
            SELECT s.*, 
                   u.full_name as driver_name, 
                   t.name as truck_name, 
                   t.plate as truck_plate, 
                   st.name as site_name 
            FROM shifts s 
            LEFT JOIN users u ON s.user_id = u.id 
            LEFT JOIN dict_trucks t ON s.truck_id = t.id 
            LEFT JOIN dict_sites st ON s.site_id = st.id 
            WHERE s.tenant_id = $1 
            ORDER BY s.created_at DESC 
            LIMIT 50`;
        const result = await pool.query(sql, [req.user.tenant_id]);
        res.json(result.rows);
    } catch (err) { res.status(500).send('Error'); }
});

app.get('/api/trucks', authenticateToken, async (req: AuthRequest, res: Response) => {
    try { const result = await pool.query('SELECT * FROM dict_trucks WHERE tenant_id = $1 AND is_active = true ORDER BY name', [req.user.tenant_id]); res.json(result.rows); } catch (err) { res.status(500).send('Error'); }
});
app.post('/api/trucks', authenticateToken, async (req: AuthRequest, res: Response) => {
    if (req.user.role !== 'admin' && req.user.role !== 'system') return res.status(403).send('Denied');
    const { name, plate, code } = req.body;
    try {
        const result = await pool.query("INSERT INTO dict_trucks (tenant_id, name, plate, code, is_active) VALUES ($1, $2, $3, $4, true) RETURNING *", [req.user.tenant_id, name, plate, code]);
        res.json(result.rows[0]);
    } catch (e) { res.status(500).send('Error'); }
});

app.get('/api/sites', authenticateToken, async (req: AuthRequest, res: Response) => {
    try { const result = await pool.query('SELECT * FROM dict_sites WHERE tenant_id = $1 AND is_active = true ORDER BY name', [req.user.tenant_id]); res.json(result.rows); } catch (err) { res.status(500).send('Error'); }
});
app.post('/api/sites', authenticateToken, async (req: AuthRequest, res: Response) => {
    if (req.user.role !== 'admin' && req.user.role !== 'system') return res.status(403).send('Denied');
    const { name, address, code } = req.body;
    try {
        const result = await pool.query("INSERT INTO dict_sites (tenant_id, name, address, code, is_active) VALUES ($1, $2, $3, $4, true) RETURNING *", [req.user.tenant_id, name, address, code]);
        res.json(result.rows[0]);
    } catch (e) { res.status(500).send('Error'); }
});

// ==========================================
// 5. SHIFT LOGIC (SMART & HUMAN READABLE)
// ==========================================

app.get('/api/shifts/current', authenticateToken, async (req: AuthRequest, res: Response) => {
    const targetUserId = req.user.role === 'system' ? req.query.user_id : req.user.id;
    try { 
        // JOIN для получения имен
        const sql = `
            SELECT s.*, 
                   t.name as truck_name, 
                   t.plate as truck_plate,
                   st.name as site_name,
                   st.address as site_address
            FROM shifts s
            LEFT JOIN dict_trucks t ON s.truck_id = t.id
            LEFT JOIN dict_sites st ON s.site_id = st.id
            WHERE s.user_id = $1 AND s.status = 'active' 
            LIMIT 1
        `;
        const result = await pool.query(sql, [targetUserId]); 
        res.json(result.rows[0] || null); 
    } catch (err) { res.status(500).send('Error'); }
});

app.post('/api/shifts/start', authenticateToken, async (req: AuthRequest, res: Response) => {
    const { truck_id, site_id, geo, photo_url, mileage } = req.body;
    
    let user_id = req.user.id;
    let tenant_id = req.user.tenant_id;

    // ИСПРАВЛЕНИЕ: Если запрос от n8n (system), находим реальный tenant_id пользователя
    if (req.user.role === 'system') {
        user_id = req.body.user_id;
        try {
            const uRes = await pool.query('SELECT tenant_id FROM users WHERE id = $1', [user_id]);
            if (uRes.rows.length > 0) {
                tenant_id = uRes.rows[0].tenant_id;
            } else {
                return res.status(404).json({ error: 'User not found' });
            }
        } catch (e) {
            console.error(e);
            return res.status(500).json({ error: 'DB Error fetching user tenant' });
        }
    }

    try {
        // Используем CTE + JOIN для возврата имен сразу после вставки
        const sql = `
            WITH inserted_shift AS (
                INSERT INTO shifts 
                (user_id, tenant_id, truck_id, site_id, start_time, status, geo_start, photo_start_url, mileage_start) 
                VALUES ($1, $2, $3, $4, NOW(), 'active', $5, $6, $7) 
                RETURNING *
            )
            SELECT 
                s.*,
                t.name as truck_name, 
                t.plate as truck_plate,
                st.name as site_name
            FROM inserted_shift s
            LEFT JOIN dict_trucks t ON s.truck_id = t.id
            LEFT JOIN dict_sites st ON s.site_id = st.id
        `;
        const result = await pool.query(sql, [user_id, tenant_id, truck_id, site_id, geo, photo_url, mileage || 0]);
        res.json(result.rows[0]);

    } catch (err: any) { 
        console.error('Shift Start Error:', err.message); 
        // Возвращаем 409 Conflict при ошибках триггера БД
        if (err.message && (err.message.includes('already has an active shift') || err.message.includes('already busy'))) {
            return res.status(409).json({ error: err.message });
        }
        res.status(500).json({ error: err.message || 'Server error' }); 
    }
});

app.post('/api/shifts/end', authenticateToken, async (req: AuthRequest, res: Response) => {
    const { geo, photo_url, mileage, comments } = req.body;
    let user_id = req.user.id;
    if (req.user.role === 'system') user_id = req.body.user_id;

    try {
        // CTE + JOIN для красивого чека
        const sql = `
            WITH updated_shift AS (
                UPDATE shifts 
                SET end_time = NOW(), 
                    status = 'finished', 
                    geo_end = $2, 
                    photo_end_url = $3, 
                    mileage_end = $4, 
                    comments = $5
                WHERE user_id = $1 AND status = 'active' 
                RETURNING *
            )
            SELECT 
                s.*,
                t.name as truck_name, 
                t.plate as truck_plate,
                st.name as site_name
            FROM updated_shift s
            LEFT JOIN dict_trucks t ON s.truck_id = t.id
            LEFT JOIN dict_sites st ON s.site_id = st.id
        `;
        const result = await pool.query(sql, [user_id, geo, photo_url, mileage || 0, comments || '']);
        
        if (result.rows.length === 0) return res.status(404).json({ error: 'Нет активной смены' });
        res.json(result.rows[0]);
    } catch (err) { console.error(err); res.status(500).send('Error'); }
});

// ==========================================
// 6. ONBOARDING (TELEGRAM / N8N WEBHOOK)
// ==========================================
app.post('/api/integrations/telegram/webhook', async (req: Request, res: Response) => {
    const { id: tgId, username, first_name, last_name, text } = req.body;

    if (!tgId) return res.status(400).json({ error: 'Missing Telegram User ID' });

    const fullName = [first_name, last_name].filter(Boolean).join(' ') || username || 'Unknown';
    const login = username || `tg_${tgId}`; 

    const client = await pool.connect();

    try {
        // 1. ПРОВЕРКА: Существует ли юзер?
        const userCheck = await client.query('SELECT * FROM users WHERE telegram_user_id = $1', [tgId]);
        
        if (userCheck.rows.length > 0) {
            const user = userCheck.rows[0];
            return res.json({
                status: 'active_user',
                message: `С возвращением, ${user.full_name}!`,
                role: user.role,
                user: user
            });
        }

        const inviteMatch = text ? text.match(/^\/start\s+(.+)$/) : null;
        const inviteCode = inviteMatch ? inviteMatch[1] : null;

        // 2. СЦЕНАРИЙ: РЕГИСТРАЦИЯ ВОДИТЕЛЯ ПО КОДУ
        if (inviteCode) {
            try {
                await client.query('BEGIN');

                const inviteRes = await client.query(
                    `SELECT * FROM invites WHERE code = $1 AND status = 'pending' AND expires_at > NOW() FOR UPDATE`,
                    [inviteCode]
                );

                if (inviteRes.rows.length === 0) {
                    await client.query('ROLLBACK');
                    return res.json({ status: 'error', message: 'Код неверный или истек.' });
                }

                const invite = inviteRes.rows[0];
                const defaultPass = await bcrypt.hash('123456', 10);

                const newUser = await client.query(
                    `INSERT INTO users (telegram_user_id, full_name, role, tenant_id, login, password_hash, is_active)
                     VALUES ($1, $2, 'driver', $3, $4, $5, true)
                     RETURNING id, full_name, role`,
                    [tgId, fullName, invite.tenant_id, login, defaultPass]
                );

                await client.query(`UPDATE invites SET status = 'used' WHERE id = $1`, [invite.id]);

                await client.query('COMMIT');

                return res.json({
                    status: 'registered_driver',
                    message: 'Вы успешно зарегистрированы как водитель.',
                    user: newUser.rows[0]
                });

            } catch (err) {
                await client.query('ROLLBACK');
                throw err;
            }
        }

        // 3. СЦЕНАРИЙ: НОВАЯ КОМПАНИЯ (АДМИН)
        try {
            await client.query('BEGIN');

            let planRes = await client.query(`SELECT id FROM plans LIMIT 1`);
            if (planRes.rows.length === 0) {
                 planRes = await client.query(`INSERT INTO plans (code, name, price_monthly) VALUES ('demo', 'Demo Plan', 0) RETURNING id`);
            }
            const planId = planRes.rows[0].id;

            const apiKey = crypto.randomBytes(32).toString('hex');

            // ШАГ 1: Создаем Тенанта БЕЗ владельца (Fix Chicken & Egg)
            const tenantRes = await client.query(
                `INSERT INTO tenants (name, plan_id, is_active, api_key, owner_user_id)
                 VALUES ($1, $2, true, $3, NULL)
                 RETURNING id`,
                [`Компания ${fullName}`, planId, apiKey]
            );
            const tenantId = tenantRes.rows[0].id;

            // ШАГ 2: Создаем Админа
            const defaultPass = await bcrypt.hash('admin123', 10);
            const adminUser = await client.query(
                `INSERT INTO users (telegram_user_id, full_name, role, tenant_id, login, password_hash, is_active)
                 VALUES ($1, $2, 'admin', $3, $4, $5, true)
                 RETURNING id, full_name, role`,
                [tgId, fullName, tenantId, login, defaultPass]
            );

            // ШАГ 3: Привязываем владельца
            await client.query(
                `UPDATE tenants SET owner_user_id = $1 WHERE id = $2`,
                [tgId, tenantId]
            );

            // Демо-данные
            await client.query(
                `INSERT INTO dict_trucks (tenant_id, code, name, plate, is_active, is_busy)
                 VALUES ($1, 'AUTO-01', 'Тестовый Грузовик', 'A777AA 77', true, false)`,
                [tenantId]
            );

            await client.query(
                `INSERT INTO dict_sites (tenant_id, code, name, address, is_active)
                 VALUES ($1, 'BASE-01', 'Главный Склад', 'г. Москва, Центр', true)`,
                [tenantId]
            );

            await client.query('COMMIT');

            return res.json({
                status: 'created_tenant',
                message: 'Компания создана! Вы администратор.',
                user: adminUser.rows[0],
                api_key: apiKey
            });

        } catch (err) {
            await client.query('ROLLBACK');
            throw err;
        }

    } catch (error) {
        console.error('Onboarding Error:', error);
        res.status(500).json({ error: 'Server error processing webhook' });
    } finally {
        client.release();
    }
});

app.listen(PORT, () => console.log(`Server on ${PORT}`));
