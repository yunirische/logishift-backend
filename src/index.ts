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

// Настройка хранилища файлов
if (!fs.existsSync(UPLOAD_DIR)) {
    fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

const storage = multer.diskStorage({
    destination: (req, file, cb) => { cb(null, UPLOAD_DIR); },
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
  if (apiKey) {
    try {
      const result = await pool.query('SELECT id FROM tenants WHERE api_key = $1', [apiKey]);
      if (result.rows.length > 0) {
        req.user = { id: 0, role: 'system', tenant_id: result.rows[0].id };
        return next();
      }
    } catch (e) { console.error(e); }
  }

  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, (err: any, user: any) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// --- ROUTES ---

// 1. ФАЙЛЫ
app.post('/api/upload', authenticateToken, upload.single('file'), (req: any, res: Response) => {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
    res.json({ url: `/uploads/${req.file.filename}` });
});

// 2. АВТОРИЗАЦИЯ
app.post('/api/auth/login', async (req: Request, res: Response) => {
  const { login, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE login = $1', [login]);
    if (result.rows.length === 0) return res.status(401).json({ error: 'User not found' });
    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) return res.status(401).json({ error: 'Invalid password' });
    const token = jwt.sign({ id: user.id, role: user.role, tenant_id: user.tenant_id }, JWT_SECRET, { expiresIn: '12h' });
    res.json({ token, user: { id: user.id, full_name: user.full_name, role: user.role } });
  } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

// 3. ПОЛЬЗОВАТЕЛИ И МЕНЮ
app.post('/api/users/set-menu-id', authenticateToken, async (req: AuthRequest, res: Response) => {
    const { message_id, user_id: bodyUserId } = req.body;
    let userId = req.user.role === 'system' ? bodyUserId : req.user.id;
    try {
        await pool.query('UPDATE users SET last_menu_message_id = $1 WHERE id = $2', [message_id, userId]);
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: 'DB error' }); }
});

// 4. СПРАВОЧНИКИ (Для n8n и фронта)
app.get('/api/trucks', authenticateToken, async (req: AuthRequest, res: Response) => {
    const tenantId = req.user.role === 'system' ? req.query.tenant_id : req.user.tenant_id;
    const result = await pool.query('SELECT * FROM dict_trucks WHERE tenant_id = $1 AND is_active = true ORDER BY name', [tenantId]);
    res.json(result.rows);
});

app.get('/api/sites', authenticateToken, async (req: AuthRequest, res: Response) => {
    const tenantId = req.user.role === 'system' ? req.query.tenant_id : req.user.tenant_id;
    const result = await pool.query('SELECT * FROM dict_sites WHERE tenant_id = $1 AND is_active = true ORDER BY name', [tenantId]);
    res.json(result.rows);
});

// 5. ЛОГИКА СМЕН
app.get('/api/shifts/current', authenticateToken, async (req: AuthRequest, res: Response) => {
    const targetUserId = req.user.role === 'system' ? req.query.user_id : req.user.id;
    const sql = `
        SELECT s.*, t.name as truck_name, t.plate as truck_plate, st.name as site_name,
               ten.timezone as tenant_timezone, ten.invoice_required as tenant_invoice_required
        FROM shifts s
        LEFT JOIN dict_trucks t ON s.truck_id = t.id
        LEFT JOIN dict_sites st ON s.site_id = st.id
        LEFT JOIN tenants ten ON s.tenant_id = ten.id
        WHERE s.user_id = $1 AND s.status IN ('active', 'pending_invoice', 'pending_truck', 'pending_site')
        ORDER BY s.id DESC LIMIT 1`;
    const result = await pool.query(sql, [targetUserId]);
    res.json(result.rows[0] || null);
});

// ==========================================
// 6. ГЛАВНЫЙ WEBHOOK (Onboarding + Команды)
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
            FROM users u LEFT JOIN tenants t ON u.tenant_id = t.id
            WHERE u.telegram_user_id = $1`, [tgId]);
        
        if (userCheck.rows.length > 0) {
            const user = userCheck.rows[0];
            if (!user.is_active) return res.json({ action: 'error_blocked', text: 'Доступ заблокирован.' });

            const cmdText = (text || '').trim();
            const cmd = cmdText.split(' ')[0];

            // А: Команды закрытия
            if (cmd === '/end_shift_now') {
                await client.query(`SELECT set_config('audit.user_id', $1, true)`, [user.id.toString()]);
                const endRes = await client.query(`UPDATE shifts SET end_time = NOW(), status = 'pending_invoice' WHERE user_id = $1 AND status = 'active' RETURNING id`, [user.id]);
                return res.json({ action: 'status', text: endRes.rows.length > 0 ? '✅ Смена закрыта. Ждем накладную.' : '⚠️ Активная смена не найдена.', user });
            }
            if (cmd === '/request_comment') return res.json({ action: 'ask_comment', text: '✍️ Введите ваш комментарий:', user });

            // Б: Параметризованные команды
            const truckMatch = cmdText.match(/\/select_truck_(\d+)/);
            if (truckMatch) {
                await client.query(`UPDATE shifts SET truck_id = $1, status = 'pending_site' WHERE user_id = $2 AND status = 'pending_truck'`, [truckMatch[1], user.id]);
                return res.json({ action: 'select_site', text: 'Машина выбрана. Теперь укажите объект:', user });
            }
            const siteMatch = cmdText.match(/\/select_site_(\d+)/);
            if (siteMatch) {
                await client.query(`UPDATE shifts SET site_id = $1, status = 'active', start_time = NOW() WHERE user_id = $2 AND status = 'pending_site'`, [siteMatch[1], user.id]);
                return res.json({ action: 'status', text: '🚀 Смена открыта!', user });
            }

            // В: Текст (Комментарий)
            if (cmdText && !cmdText.startsWith('/')) {
                await client.query(`SELECT set_config('audit.user_id', $1, true)`, [user.id.toString()]);
                const updateRes = await client.query(`UPDATE shifts SET end_time = NOW(), status = 'pending_invoice', comment = $1 WHERE user_id = $2 AND status = 'active' RETURNING id`, [cmdText, user.id]);
                return res.json({ action: 'status', text: updateRes.rows.length > 0 ? '✅ Смена закрыта с комментарием.' : '⚠️ Активная смена не найдена.', user });
            }

            // Г: Роутинг
            let action = 'show_driver_menu';
            let responseText = `С возвращением, ${user.full_name}!`;
            if (cmd === '/status') action = 'status';
            else if (cmd === '/driver') action = 'show_driver_menu';
            else if (cmd === '/admin' && user.role === 'admin') action = 'show_admin_menu';
            else if (cmd === '/start_shift') {
                const activeShift = await client.query(`SELECT id FROM shifts WHERE user_id = $1 AND status != 'finished'`, [user.id]);
                if (activeShift.rows.length === 0) await client.query(`INSERT INTO shifts (user_id, tenant_id, status) VALUES ($1, $2, 'pending_truck')`, [user.id, user.tenant_id]);
                action = 'start_shift';
            } else if (cmd === '/end_shift') {
                const checkShift = await client.query(`SELECT status FROM shifts WHERE user_id = $1 AND status != 'finished' LIMIT 1`, [user.id]);
                const currentStatus = checkShift.rows[0]?.status;
                if (currentStatus === 'pending_invoice') { action = 'status'; responseText = '⏳ Смена уже ждет накладную.'; }
                else if (!currentStatus) { action = 'show_driver_menu'; responseText = '❌ Нет активной смены.'; }
                else action = 'end_shift';
            }

            return res.json({ action, text: responseText, user });
        }

        // Д: РЕГИСТРАЦИЯ
        const inviteMatch = text ? text.match(/^\/start\s+(.+)$/) : null;
        if (inviteMatch) {
            await client.query('BEGIN');
            const inviteRes = await client.query(`SELECT * FROM invites WHERE code = $1 AND status = 'pending' AND expires_at > NOW() FOR UPDATE`, [inviteMatch[1]]);
            if (inviteRes.rows.length === 0) { await client.query('ROLLBACK'); return res.json({ action: 'ask_invite', text: 'Код неверен.' }); }
            const hash = await bcrypt.hash('123456', 10);
            const newUser = await client.query(`INSERT INTO users (telegram_user_id, full_name, role, tenant_id, login, password_hash, is_active) VALUES ($1, $2, 'driver', $3, $4, $5, true) RETURNING *`, [tgId, fullName, inviteRes.rows[0].tenant_id, login, hash]);
            await client.query(`UPDATE invites SET status = 'used' WHERE id = $1`, [inviteRes.rows[0].id]);
            await client.query('COMMIT');
            return res.json({ action: 'show_driver_menu', text: 'Регистрация успешна! Пароль: 123456', user: newUser.rows[0] });
        }

        // Е: НОВЫЙ АДМИН + КОМПАНИЯ + ДЕМО
        await client.query('BEGIN');
        const apiKey = crypto.randomBytes(32).toString('hex');
        const hash = await bcrypt.hash('admin123', 10);
        let planRes = await client.query(`SELECT id FROM plans LIMIT 1`);
        const planId = planRes.rows.length > 0 ? planRes.rows[0].id : (await client.query(`INSERT INTO plans (code, name, price_monthly) VALUES ('demo', 'Demo', 0) RETURNING id`)).rows[0].id;
        const tenantRes = await client.query(`INSERT INTO tenants (name, plan_id, is_active, api_key) VALUES ($1, $2, true, $3) RETURNING id`, [`Компания ${fullName}`, planId, apiKey]);
        const adminUser = await client.query(`INSERT INTO users (telegram_user_id, full_name, role, tenant_id, login, password_hash, is_active) VALUES ($1, $2, 'admin', $3, $4, $5, true) RETURNING *`, [tgId, fullName, tenantRes.rows[0].id, login, hash]);
        await client.query(`UPDATE tenants SET owner_user_id = $1 WHERE id = $2`, [adminUser.rows[0].id, tenantRes.rows[0].id]);
        await client.query(`INSERT INTO dict_trucks (tenant_id, name, plate, is_active) VALUES ($1, 'Тестовый Камаз', 'А001АА 77', true)`, [tenantRes.rows[0].id]);
        await client.query(`INSERT INTO dict_sites (tenant_id, name, address, is_active) VALUES ($1, 'База Центр', 'ул. Ленина, 1', true)`, [tenantRes.rows[0].id]);
        await client.query('COMMIT');
        return res.json({ action: 'show_admin_menu', text: 'Компания создана! Пароль: admin123', user: adminUser.rows[0], api_key: apiKey });

    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ error: 'Server Error' });
    } finally { client.release(); }
});

app.listen(PORT, () => console.log(`Server on ${PORT}`));
