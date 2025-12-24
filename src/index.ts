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
const UPLOAD_DIR = '/app/uploads'; 
const CDN_URL = 'https://bot.kontrolsmen.ru/uploads'; 

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

const storage = multer.diskStorage({
    destination: (req: any, file, cb) => {
        const tenantId = req.user?.tenant_id || 'unknown';
        const now = new Date();
        const finalDir = path.join(UPLOAD_DIR, tenantId.toString(), now.getFullYear().toString(), (now.getMonth() + 1).toString().padStart(2, '0'));
        if (!fs.existsSync(finalDir)) fs.mkdirSync(finalDir, { recursive: true });
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

interface AuthRequest extends Request { user?: any; }
const authenticateToken = async (req: AuthRequest, res: Response, next: NextFunction) => {
    const apiKey = req.headers['x-api-key'] as string;
    if (apiKey) {
        try {
            const result = await pool.query('SELECT id FROM tenants WHERE api_key = $1', [apiKey]);
            if (result.rows.length > 0) {
                req.user = { id: 0, role: 'system', tenant_id: result.rows[0].id };
                return next();
            }
        } catch (e) { console.error('Auth Error:', e); }
    }
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.sendStatus(401);
    jwt.verify(token, JWT_SECRET, (err: any, user: any) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// --- МЕТОДЫ API ---

app.post('/api/upload', authenticateToken, upload.single('file'), (req: any, res: Response) => {
    if (!req.file) return res.status(400).json({ error: 'Файл не загружен' });
    res.json({ url: req.file.path.replace(UPLOAD_DIR, '') });
});

app.post('/api/users/set-menu-id', authenticateToken, async (req: AuthRequest, res: Response) => {
    const { message_id, user_id: bodyUserId } = req.body;
    const userId = req.user.role === 'system' ? bodyUserId : req.user.id;
    await pool.query('UPDATE users SET last_menu_message_id = $1 WHERE id = $2', [message_id, userId]);
    res.json({ success: true });
});

app.get('/api/shifts/current', authenticateToken, async (req: AuthRequest, res: Response) => {
    const targetUserId = req.user.role === 'system' ? req.query.user_id : req.user.id;
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
        if (shift.photo_start_url) shift.photo_start_url = `${CDN_URL}${shift.photo_start_url}`;
        if (shift.photo_end_url) shift.photo_end_url = `${CDN_URL}${shift.photo_end_url}`;
        if (shift.photo_invoice_url) shift.photo_invoice_url = `${CDN_URL}${shift.photo_invoice_url}`;
    }
    res.json(shift || null);
});

// --- ГЛАВНЫЙ WEBHOOK ---

app.post('/api/integrations/telegram/webhook', async (req: Request, res: Response) => {
    const { id: tgId, text, photo_url, username, first_name, last_name } = req.body;
    const client = await pool.connect();
    const fullName = [first_name, last_name].filter(Boolean).join(' ') || username || 'Unknown';
    const login = username || `tg_${tgId}`;

    try {
        const userRes = await client.query(`
            SELECT u.*, t.timezone, t.invoice_required as tenant_invoice_required 
            FROM users u LEFT JOIN tenants t ON u.tenant_id = t.id
            WHERE u.telegram_user_id = $1`, [tgId]);
        
        if (userRes.rows.length === 0) {
            // ... (регистрация и создание компании остаются без изменений) ...
            // Для краткости я не дублирую блок регистрации, он в прошлом сообщении был верным
        }

        const user = userRes.rows[0];
        await client.query(`SELECT set_config('audit.user_id', $1, true)`, [user.id.toString()]);
        const cmdText = (text || '').trim();
        const cmd = cmdText.split(' ')[0];

        // --- 1. ОБРАБОТКА ФОТО (Улучшенная) ---
        if (text === 'PHOTO_UPLOADED') {
            const shiftRes = await client.query(`
                SELECT s.*, st.odometer_required 
                FROM shifts s LEFT JOIN dict_sites st ON s.site_id = st.id 
                WHERE s.user_id = $1 AND s.status != 'finished' LIMIT 1`, [user.id]);
            const shift = shiftRes.rows[0];
            if (!shift) return res.json({ action: 'show_driver_menu', text: '⚠️ Смена не найдена для привязки фото.', user });

            // А. Одометр СТАРТ
            if (shift.status === 'active' && shift.odometer_required && !shift.photo_start_url) {
                await client.query(`UPDATE shifts SET photo_start_url = $1 WHERE id = $2`, [photo_url, shift.id]);
                return res.json({ action: 'status', text: '✅ <b>Фото одометра (старт) принято!</b>\nТеперь вы на смене. Хорошего пути!', user });
            }
            // Б. Одометр ФИНИШ
            if (shift.status === 'active' && shift.odometer_required && shift.photo_start_url && !shift.photo_end_url) {
                await client.query(`UPDATE shifts SET photo_end_url = $1 WHERE id = $2`, [photo_url, shift.id]);
                if (user.tenant_invoice_required) {
                    await client.query(`UPDATE shifts SET status = 'pending_invoice' WHERE id = $1`, [shift.id]);
                    return res.json({ action: 'ask_photo', text: '📸 <b>Одометр (финиш) принят!</b>\nПоследний шаг: пришлите фото НАКЛАДНОЙ.', user });
                } else {
                    await client.query(`UPDATE shifts SET status = 'finished', end_time = NOW() WHERE id = $1`, [shift.id]);
                    return res.json({ action: 'status', text: '🏁 <b>Смена завершена!</b>\nОдометр зафиксирован. Отдыхайте.', user });
                }
            }
            // В. НАКЛАДНАЯ
            if (shift.status === 'pending_invoice') {
                await client.query(`UPDATE shifts SET photo_invoice_url = $1, status = 'finished', end_time = NOW() WHERE id = $2`, [photo_url, shift.id]);
                return res.json({ action: 'status', text: '✅ <b>Накладная принята!</b>\nСмена полностью закрыта. Спасибо за работу.', user });
            }
        }

        // --- 2. ВЫБОР ОБЪЕКТА / МАШИНЫ (С защитой) ---
        const siteMatch = cmdText.match(/\/select_site_(\d+)/);
        if (siteMatch) {
            const siteId = siteMatch[1];
            const siteInfo = await client.query(`SELECT name, odometer_required FROM dict_sites WHERE id = $1`, [siteId]);
            await client.query(`UPDATE shifts SET site_id = $1, status = 'active', start_time = NOW() WHERE user_id = $2 AND status = 'pending_site'`, [siteId, user.id]);
            const odoMsg = siteInfo.rows[0]?.odometer_required ? '\n\n📸 <b>Внимание:</b> Для этого объекта нужно фото одометра. Пришлите его прямо сейчас.' : '';
            return res.json({ action: siteInfo.rows[0]?.odometer_required ? 'ask_photo' : 'status', text: `🚀 Смена открыта на объекте <b>${siteInfo.rows[0].name}</b>!${odoMsg}`, user });
        }
        const truckMatch = cmdText.match(/\/select_truck_(\d+)/);
        if (truckMatch) {
            await client.query(`UPDATE shifts SET truck_id = $1, status = 'pending_site' WHERE user_id = $2 AND status = 'pending_truck'`, [truckMatch[1], user.id]);
            return res.json({ action: 'select_site', text: '🚚 Машина выбрана. Теперь укажите объект работы:', user });
        }

        // --- 3. ЗАВЕРШЕНИЕ СМЕНЫ ---
        if (cmd === '/end_shift' || cmd === '/end_shift_now' || (cmdText && !cmdText.startsWith('/'))) {
            const shiftRes = await client.query(`SELECT s.*, st.odometer_required FROM shifts s LEFT JOIN dict_sites st ON s.site_id = st.id WHERE s.user_id = $1 AND s.status = 'active' LIMIT 1`, [user.id]);
            const shift = shiftRes.rows[0];
            
            if (!shift) {
                const pending = await client.query(`SELECT status FROM shifts WHERE user_id = $1 AND status = 'pending_invoice'`, [user.id]);
                if (pending.rows.length > 0) return res.json({ action: 'status', text: '⏳ Смена уже ожидает накладную. Пришлите фото.', user });
                return res.json({ action: 'show_driver_menu', text: '❌ У вас нет активной смены для завершения.', user });
            }

            if (!cmdText.startsWith('/')) await client.query(`UPDATE shifts SET comment = $1 WHERE id = $2`, [cmdText, shift.id]);

            if (shift.odometer_required && !shift.photo_end_url) {
                return res.json({ action: 'ask_photo', text: '🏁 <b>Завершение смены:</b>\nПожалуйста, пришлите фото ОДОМЕТРА.', user });
            }
            if (user.tenant_invoice_required) {
                await client.query(`UPDATE shifts SET status = 'pending_invoice' WHERE id = $1`, [shift.id]);
                return res.json({ action: 'ask_photo', text: '🏁 <b>Завершение смены:</b>\nПришлите фото НАКЛАДНОЙ.', user });
            }
            await client.query(`UPDATE shifts SET status = 'finished', end_time = NOW() WHERE id = $1`, [shift.id]);
            return res.json({ action: 'status', text: '🏁 Смена успешно закрыта!', user });
        }

        // --- 4. РОУТИНГ КОМАНД (С блокировкой дублей) ---
        let action = 'show_driver_menu';
        let responseText = 'Выберите действие:';

        if (cmd === '/start_shift') {
            const activeShift = await client.query(`SELECT id, status FROM shifts WHERE user_id = $1 AND status != 'finished' LIMIT 1`, [user.id]);
            if (activeShift.rows.length > 0) {
                return res.json({ action: 'status', text: '⚠️ У вас уже есть открытая смена или черновик. Нельзя начать новую, пока не закроете старую.', user });
            }
            await client.query(`INSERT INTO shifts (user_id, tenant_id, status) VALUES ($1, $2, 'pending_truck')`, [user.id, user.tenant_id]);
            action = 'start_shift';
        } else if (cmd === '/status') action = 'status';
        else if (cmd === '/driver') action = 'show_driver_menu';
        else if (cmd === '/admin' && user.role === 'admin') action = 'show_admin_menu';

        return res.json({ action, text: responseText, user });

    } catch (e) {
        console.error('Fatal Webhook Error:', e);
        res.status(500).json({ error: 'Internal Server Error' });
    } finally { client.release(); }
});

app.listen(PORT, () => console.log(`Server on ${PORT}`));
