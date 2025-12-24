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

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'secret';

// ПУТЬ К ВАШЕЙ ПАПКЕ
const UPLOAD_DIR = '/app/uploads'; 

// --- БЛОК 1: ПОДКЛЮЧЕНИЕ К БАЗЕ ДАННЫХ ---
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

// --- БЛОК 2: НАСТРОЙКА СИСТЕМНОГО ХРАНИЛИЩА (Multer) ---
const storage = multer.diskStorage({
    destination: (req: any, file, cb) => {
        const tenantId = req.user?.tenant_id || 'unknown';
        const now = new Date();
        const year = now.getFullYear().toString();
        const month = (now.getMonth() + 1).toString().padStart(2, '0');
        const finalDir = path.join(UPLOAD_DIR, tenantId.toString(), year, month);

        if (!fs.existsSync(finalDir)) {
            fs.mkdirSync(finalDir, { recursive: true });
        }
        cb(null, finalDir);
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + path.extname(file.originalname));
    }
});
const upload = multer({ storage: storage });

app.use(cors());
app.use(express.json());

// --- БЛОК 3: ЗАЩИТА (MIDDLEWARE) ---
interface AuthRequest extends Request { user?: any; }
const authenticateToken = async (req: AuthRequest, res: Response, next: NextFunction) => {
    const apiKey = req.headers['x-api-key'] as string;
    if (apiKey) {
        const result = await pool.query('SELECT id FROM tenants WHERE api_key = $1', [apiKey]);
        if (result.rows.length > 0) {
            req.user = { id: 0, role: 'system', tenant_id: result.rows[0].id };
            return next();
        }
    }
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.sendStatus(401);
    jwt.verify(token, JWT_SECRET, (err: any, user: any) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// --- БЛОК 4: API ДЛЯ ЗАГРУЗКИ ФОТО ---
app.post('/api/upload', authenticateToken, upload.single('file'), (req: any, res: Response) => {
    if (!req.file) return res.status(400).json({ error: 'Файл не загружен' });
    const relativePath = req.file.path.replace(UPLOAD_DIR, '');
    res.json({ url: relativePath });
});

// --- БЛОК 5: ЛОГИКА ДАННЫХ (SHIFTS & DICTS) ---

// 5.1 Текущая смена (с полными ссылками на фото)
app.get('/api/shifts/current', authenticateToken, async (req: AuthRequest, res: Response) => {
    const targetUserId = req.user.role === 'system' ? req.query.user_id : req.user.id;
    
    // Укажи здесь свой домен, где лежат файлы
    const CDN_URL = 'https://bot.kontrolsmen.ru/uploads'; 

    const sql = `
        SELECT s.*, t.name as truck_name, t.plate as truck_plate, 
               st.name as site_name, st.odometer_required as site_odometer_required,
               ten.timezone as tenant_timezone, ten.invoice_required as tenant_invoice_required
        FROM shifts s
        LEFT JOIN dict_trucks t ON s.truck_id = t.id
        LEFT JOIN dict_sites st ON s.site_id = st.id
        LEFT JOIN tenants ten ON s.tenant_id = ten.id
        WHERE s.user_id = $1 AND s.status != 'finished'
        ORDER BY s.id DESC LIMIT 1`;
        
    const result = await pool.query(sql, [targetUserId]);
    const shift = result.rows[0];

    if (shift) {
        // Если фото есть, приклеиваем домен
        if (shift.photo_start_url) shift.photo_start_url = `${CDN_URL}${shift.photo_start_url}`;
        if (shift.photo_end_url) shift.photo_end_url = `${CDN_URL}${shift.photo_end_url}`;
    }

    res.json(shift || null);
});

// 5.2 Сохранить ID сообщения меню (Чистый чат)
app.post('/api/users/set-menu-id', authenticateToken, async (req: AuthRequest, res: Response) => {
    const { message_id, user_id: bodyUserId } = req.body;
    const userId = req.user.role === 'system' ? bodyUserId : req.user.id;
    await pool.query('UPDATE users SET last_menu_message_id = $1 WHERE id = $2', [message_id, userId]);
    res.json({ success: true });
});

// 5.3 Список машин (ДЛЯ n8n)
app.get('/api/trucks', authenticateToken, async (req: AuthRequest, res: Response) => {
    try {
        const tenantId = req.user.role === 'system' ? req.query.tenant_id : req.user.tenant_id;
        const result = await pool.query(
            'SELECT * FROM dict_trucks WHERE tenant_id = $1 AND is_active = true ORDER BY name', 
            [tenantId]
        );
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: 'Database error' }); }
});

// 5.4 Список объектов (ДЛЯ n8n)
app.get('/api/sites', authenticateToken, async (req: AuthRequest, res: Response) => {
    try {
        const tenantId = req.user.role === 'system' ? req.query.tenant_id : req.user.tenant_id;
        const result = await pool.query(
            'SELECT * FROM dict_sites WHERE tenant_id = $1 AND is_active = true ORDER BY name', 
            [tenantId]
        );
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: 'Database error' }); }
});

// --- БЛОК 6: ГЛАВНЫЙ ОБРАБОТЧИК (WEBHOOK) ---
app.post('/api/integrations/telegram/webhook', async (req: Request, res: Response) => {
    const { id: tgId, text, photo_url } = req.body;
    const client = await pool.connect();

    try {
        const userRes = await client.query(`
            SELECT u.*, t.timezone, t.invoice_required as tenant_invoice_required 
            FROM users u LEFT JOIN tenants t ON u.tenant_id = t.id
            WHERE u.telegram_user_id = $1`, [tgId]);
        
        if (userRes.rows.length === 0) return res.json({ action: 'ask_invite', text: 'Вы не зарегистрированы.' });
        const user = userRes.rows[0];
        await client.query(`SELECT set_config('audit.user_id', $1, true)`, [user.id.toString()]);

        const cmdText = (text || '').trim();
        const cmd = cmdText.split(' ')[0];

        // 6.1 ОБРАБОТКА ФОТО (Накладные / Одометры)
        if (text === 'PHOTO_UPLOADED') {
            const shiftRes = await client.query(`
                SELECT s.*, st.odometer_required 
                FROM shifts s LEFT JOIN dict_sites st ON s.site_id = st.id 
                WHERE s.user_id = $1 AND s.status != 'finished' LIMIT 1`, [user.id]);
            const shift = shiftRes.rows[0];
            if (!shift) return res.json({ action: 'show_driver_menu', text: 'Смена не найдена.', user });

            if (shift.status === 'active' && shift.odometer_required && !shift.photo_start_url) {
                await client.query(`UPDATE shifts SET photo_start_url = $1 WHERE id = $2`, [photo_url, shift.id]);
                return res.json({ action: 'status', text: '📸 Фото одометра (старт) принято!', user });
            }
            if (shift.status === 'active' && shift.odometer_required && shift.photo_start_url && !shift.photo_end_url) {
                await client.query(`UPDATE shifts SET photo_end_url = $1 WHERE id = $2`, [photo_url, shift.id]);
                if (user.tenant_invoice_required) {
                    await client.query(`UPDATE shifts SET status = 'pending_invoice' WHERE id = $1`, [shift.id]);
                    return res.json({ action: 'ask_photo', text: '✅ Одометр принят. Пришлите фото НАКЛАДНОЙ.', user });
                } else {
                    await client.query(`UPDATE shifts SET status = 'finished', end_time = NOW() WHERE id = $1`, [shift.id]);
                    return res.json({ action: 'status', text: '🏁 Смена завершена!', user });
                }
            }
            if (shift.status === 'pending_invoice') {
                await client.query(`UPDATE shifts SET photo_end_url = COALESCE(photo_end_url, $1), status = 'finished', end_time = NOW() WHERE id = $2`, [photo_url, shift.id]);
                return res.json({ action: 'status', text: '✅ Накладная принята. Смена закрыта!', user });
            }
        }

        // 6.2 ВЫБОР ОБЪЕКТА (СТАРТ)
        const siteMatch = cmdText.match(/\/select_site_(\d+)/);
        if (siteMatch) {
            const siteId = siteMatch[1];
            const siteInfo = await client.query(`SELECT odometer_required FROM dict_sites WHERE id = $1`, [siteId]);
            await client.query(`UPDATE shifts SET site_id = $1, status = 'active', start_time = NOW() WHERE user_id = $2 AND status = 'pending_site'`, [siteId, user.id]);
            if (siteInfo.rows[0]?.odometer_required) {
                return res.json({ action: 'ask_photo', text: '📸 Объект требует фото одометра. Пришлите его.', user });
            }
            return res.json({ action: 'status', text: '🚀 Смена открыта!', user });
        }

        // 6.3 ВЫБОР МАШИНЫ
        const truckMatch = cmdText.match(/\/select_truck_(\d+)/);
        if (truckMatch) {
            await client.query(`UPDATE shifts SET truck_id = $1, status = 'pending_site' WHERE user_id = $2 AND status = 'pending_truck'`, [truckMatch[1], user.id]);
            return res.json({ action: 'select_site', text: 'Теперь укажите объект:', user });
        }

        // 6.4 ЗАВЕРШЕНИЕ СМЕНЫ
        if (cmd === '/end_shift' || cmd === '/end_shift_now' || (cmdText && !cmdText.startsWith('/'))) {
            const shiftRes = await client.query(`SELECT s.*, st.odometer_required FROM shifts s LEFT JOIN dict_sites st ON s.site_id = st.id WHERE s.user_id = $1 AND s.status = 'active' LIMIT 1`, [user.id]);
            const shift = shiftRes.rows[0];

            if (!shift) {
                if (cmdText.startsWith('/')) return res.json({ action: 'status', text: 'Активной смены нет.', user });
                return res.json({ action: 'show_driver_menu', text: 'Меню', user });
            }

            const comment = cmdText.startsWith('/') ? null : cmdText;
            await client.query(`UPDATE shifts SET comment = $1 WHERE id = $2`, [comment, shift.id]);

            if (shift.odometer_required && !shift.photo_end_url) {
                return res.json({ action: 'ask_photo', text: '📸 Для закрытия нужно фото одометра. Пришлите его.', user });
            }
            if (user.tenant_invoice_required) {
                await client.query(`UPDATE shifts SET status = 'pending_invoice' WHERE id = $1`, [shift.id]);
                return res.json({ action: 'ask_photo', text: '🏁 Пришлите фото НАКЛАДНОЙ.', user });
            }
            await client.query(`UPDATE shifts SET status = 'finished', end_time = NOW() WHERE id = $1`, [shift.id]);
            return res.json({ action: 'status', text: '🏁 Смена закрыта!', user });
        }

        // 6.5 РОУТИНГ КОМАНД
        let action = 'show_driver_menu';
        if (cmd === '/start_shift') {
            const hasShift = await client.query(`SELECT id FROM shifts WHERE user_id = $1 AND status != 'finished'`, [user.id]);
            if (hasShift.rows.length === 0) await client.query(`INSERT INTO shifts (user_id, tenant_id, status) VALUES ($1, $2, 'pending_truck')`, [user.id, user.tenant_id]);
            action = 'start_shift';
        } else if (cmd === '/status') action = 'status';
        else if (cmd === '/driver') action = 'show_driver_menu';
        else if (cmd === '/admin' && user.role === 'admin') action = 'show_admin_menu';

        return res.json({ action, text: 'Меню', user });

    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Ошибка сервера' });
    } finally {
        client.release();
    }
});

app.listen(PORT, () => console.log(`API на порту ${PORT}`));
