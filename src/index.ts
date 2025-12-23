import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import { Pool } from 'pg';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import multer from 'multer';
import * as path from 'path';
import * as fs from 'fs';
import * as crypto from 'crypto';

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
        req.user = { id: 0, role: 'system', tenant_id: result.rows[0].id };
        return next();
      }
    } catch (e) { console.error(e); }
  }

  // 2. Проверка Bearer Token (для фронтенда)
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, (err: any, user: any) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// --- ROUTES ---
// [ВСЕ ROUTES ОСТАЮТСЯ БЕЗ ИЗМЕНЕНИЙ - auth, users, dashboard, shifts, etc.]
// ✅ 1. СОХРАНЕНИЕ ID МЕНЮ (Для чистого чата)
app.post('/api/users/set-menu-id', authenticateToken, async (req: AuthRequest, res: Response) => {
    const { message_id, user_id: bodyUserId } = req.body;
    let userId = req.user.id;
    
    // Если запрос от n8n (role: system), берем user_id из тела запроса
    if (req.user.role === 'system') userId = bodyUserId;

    if (!userId || !message_id) return res.status(400).json({ error: 'Missing data' });

    try {
        await pool.query('UPDATE users SET last_menu_message_id = $1 WHERE id = $2', [message_id, userId]);
        res.json({ success: true });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Database error' });
    }
});

// ✅ 2. ПОЛУЧЕНИЕ СПИСКА МАШИН (Для Driver_Start)
app.get('/api/trucks', authenticateToken, async (req: AuthRequest, res: Response) => {
    try { 
        const tenantId = req.user.role === 'system' ? req.query.tenant_id : req.user.tenant_id;
        const result = await pool.query(
            'SELECT * FROM dict_trucks WHERE tenant_id = $1 AND is_active = true ORDER BY name', 
            [tenantId]
        ); 
        res.json(result.rows); 
    } catch (err) { res.status(500).send('Error'); }
});

// ✅ 3. ПОЛУЧЕНИЕ СПИСКА ОБЪЕКТОВ (Для Driver_Start)
app.get('/api/sites', authenticateToken, async (req: AuthRequest, res: Response) => {
    try { 
        const tenantId = req.user.role === 'system' ? req.query.tenant_id : req.user.tenant_id;
        const result = await pool.query(
            'SELECT * FROM dict_sites WHERE tenant_id = $1 AND is_active = true ORDER BY name', 
            [tenantId]
        ); 
        res.json(result.rows); 
    } catch (err) { res.status(500).send('Error'); }
});

// ✅ 4. ПОЛУЧЕНИЕ ТЕКУЩЕЙ СМЕНЫ (Для Driver_Status)
app.get('/api/shifts/current', authenticateToken, async (req: AuthRequest, res: Response) => {
    const targetUserId = req.user.role === 'system' ? req.query.user_id : req.user.id;
    if (!targetUserId) return res.status(400).json({ error: 'Missing user_id' });

    try { 
        const sql = `
            SELECT s.*, t.name as truck_name, t.plate as truck_plate, st.name as site_name,
                   ten.timezone as tenant_timezone, ten.invoice_required as tenant_invoice_required
            FROM shifts s
            LEFT JOIN dict_trucks t ON s.truck_id = t.id
            LEFT JOIN dict_sites st ON s.site_id = st.id
            LEFT JOIN tenants ten ON s.tenant_id = ten.id
            WHERE s.user_id = $1 AND s.status IN ('active', 'pending_invoice', 'pending_truck', 'pending_site')
            ORDER BY s.id DESC LIMIT 1
        `;
        const result = await pool.query(sql, [targetUserId]); 
        res.json(result.rows[0] || null); 
    } catch (err) { res.status(500).json({ error: 'Internal server error' }); }
});

// ==========================================
// 6. ONBOARDING (TELEGRAM / N8N WEBHOOK) - ИСПРАВЛЕННАЯ ВЕРСИЯ
// ==========================================
app.post('/api/integrations/telegram/webhook', async (req: Request, res: Response) => {
    const { id: tgId, username, first_name, last_name, text } = req.body;

    if (!tgId) return res.status(400).json({ error: 'Missing Telegram User ID' });

    const fullName = [first_name, last_name].filter(Boolean).join(' ') || username || 'Unknown';
    const login = username || `tg_${tgId}`; 

    const client = await pool.connect();

    try {
        const userCheck = await client.query(`
            SELECT u.*, t.timezone, t.invoice_required 
            FROM users u
            LEFT JOIN tenants t ON u.tenant_id = t.id
            WHERE u.telegram_user_id = $1
        `, [tgId]);
        
        if (userCheck.rows.length > 0) {
            const user = userCheck.rows[0];
            const cmdText = text || '';

            // 1. Если нажали "Завершить сейчас" (без комментария)
            if (cmdText === '/end_shift_now') {
                await client.query(
                    `UPDATE shifts 
                     SET end_time = NOW(), status = 'pending_invoice' 
                     WHERE user_id = $1 AND status = 'active'`,
                    [user.id]
                );
                return res.json({
                    action: 'status', // После закрытия сразу показываем статус (что нужна накладная)
                    text: '✅ Смена зафиксирована. Теперь, пожалуйста, пришлите фото накладной.',
                    user: user
                });
            }

            // 2. Если нажали "Добавить комментарий"
            if (cmdText === '/request_comment') {
                return res.json({
                    action: 'ask_comment',
                    text: '✍️ Пожалуйста, введите ваш комментарий к смене (например, о простое или поломке):',
                    user: user
                });
            }

            // Остальной дефолтный ответ для активного юзера
            return res.json({
                status: 'active_user',
                message: `С возвращением, ${user.full_name}!`,
                role: user.role,
                user: {
                    ...user,
                    tenant_settings: {
                        timezone: user.timezone,
                        invoice_required: user.invoice_required
                    }
                }
            });
        }

        // ---- дальше твои сценарии инвайта и создания компании без изменений ----
        const inviteMatch = text ? text.match(/^\/start\s+(.+)$/) : null;
        const inviteCode = inviteMatch ? inviteMatch[1] : null;

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

        // 3. Сценарий новой компании (админ) — как у тебя было
        try {
            await client.query('BEGIN');

            let planRes = await client.query(`SELECT id FROM plans LIMIT 1`);
            if (planRes.rows.length === 0) {
                 planRes = await client.query(
                    `INSERT INTO plans (code, name, price_monthly) 
                     VALUES ('demo', 'Demo Plan', 0) RETURNING id`
                 );
            }
            const planId = planRes.rows[0].id;

            const apiKey = crypto.randomBytes(32).toString('hex');

            const tenantRes = await client.query(
                `INSERT INTO tenants (name, plan_id, is_active, api_key, owner_user_id)
                 VALUES ($1, $2, true, $3, NULL)
                 RETURNING id`,
                [`Компания ${fullName}`, planId, apiKey]
            );
            const tenantId = tenantRes.rows[0].id;

            const defaultPass = await bcrypt.hash('admin123', 10);
            const adminUser = await client.query(
                `INSERT INTO users (telegram_user_id, full_name, role, tenant_id, login, password_hash, is_active)
                 VALUES ($1, $2, 'admin', $3, $4, $5, true)
                 RETURNING id, full_name, role`,
                [tgId, fullName, tenantId, login, defaultPass]
            );

            await client.query(
                `UPDATE tenants SET owner_user_id = $1 WHERE id = $2`,
                [tgId, tenantId]
            );

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
