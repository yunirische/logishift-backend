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

// --- ХРАНИЛИЩЕ ---
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

// --- ЗАЩИТА ---
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

// --- ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ---
async function finalizeShift(client: any, shiftId: number) {
    await client.query(`
        UPDATE shifts 
        SET status = 'finished', end_time = NOW(), invoice_requested_at = NULL,
            hours_worked = ROUND((EXTRACT(EPOCH FROM (NOW() - start_time)) / 3600)::numeric, 2)
        WHERE id = $1`, [shiftId]);
}

// --- СПРАВОЧНИКИ ---
app.get('/api/trucks', authenticateToken, async (req: AuthRequest, res: Response) => {
    const tId = req.user.role === 'system' ? req.query.tenant_id : req.user.tenant_id;
    const result = await pool.query('SELECT * FROM dict_trucks WHERE tenant_id = $1 AND is_active = true ORDER BY name', [tId]);
    res.json(result.rows);
});

app.get('/api/sites', authenticateToken, async (req: AuthRequest, res: Response) => {
    const tId = req.user.role === 'system' ? req.query.tenant_id : req.user.tenant_id;
    const result = await pool.query('SELECT * FROM dict_sites WHERE tenant_id = $1 AND is_active = true ORDER BY name', [tId]);
    res.json(result.rows);
});

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
        const wrap = (p: string) => p ? `${CDN_URL}${p}` : null;
        shift.photo_start_url = wrap(shift.photo_start_url);
        shift.photo_end_url = wrap(shift.photo_end_url);
        shift.photo_invoice_url = wrap(shift.photo_invoice_url);
    }
    res.json(shift || null);
});

// --- ГЛАВНЫЙ WEBHOOK ---
app.post('/api/integrations/telegram/webhook', async (req: Request, res: Response) => {
    const { id: tgId, photo_url } = req.body;
    let rawText = (req.body.text || '').trim();
    
    // ФИКС ДЛЯ n8n: Если текст пустой, но есть объект data (нажата кнопка)
    if (!rawText && req.body.data) {
        rawText = typeof req.body.data === 'string' ? req.body.data : JSON.stringify(req.body.data);
    }

    const client = await pool.connect();

    try {
        // 1. НОРМАЛИЗАЦИЯ КОМАНД
        let internalCmd = rawText.toUpperCase();
        let paramId: string | null = null;

        if (rawText.startsWith('{')) {
            try {
                const json = JSON.parse(rawText);
                if (json.intent === 'add_truck') { internalCmd = 'TRK'; paramId = json.truck_id.toString(); }
                if (json.intent === 'add_site') { internalCmd = 'STE'; paramId = json.site_id.toString(); }
                if (json.data && json.data.adm === 'end_shift_now') { internalCmd = 'END_SHIFT_NOW'; }
            } catch (e) {}
        } else if (rawText.startsWith('/')) {
            const clean = rawText.substring(1).toUpperCase();
            if (clean.includes('SELECT_TRUCK_')) { internalCmd = 'TRK'; paramId = clean.replace('SELECT_TRUCK_', ''); }
            else if (clean.includes('SELECT_SITE_')) { internalCmd = 'STE'; paramId = clean.replace('SELECT_SITE_', ''); }
            else internalCmd = clean;
        }

        // 2. ПОИСК ЮЗЕРА
        const userRes = await client.query(`
            SELECT u.*, t.timezone, t.invoice_required as tenant_invoice_required 
            FROM users u LEFT JOIN tenants t ON u.tenant_id = t.id
            WHERE u.telegram_user_id = $1`, [tgId]);
        
        if (userRes.rows.length === 0) return res.json({ action: 'ask_invite', text: 'Зарегистрируйтесь.' });
        const user = userRes.rows[0];
        await client.query(`SELECT set_config('audit.user_id', $1, true)`, [user.id.toString()]);

        // 3. ОБРАБОТКА ФОТО
        if (rawText === 'PHOTO_UPLOADED') {
            const shiftRes = await client.query(`SELECT s.*, st.odometer_required FROM shifts s LEFT JOIN dict_sites st ON s.site_id = st.id WHERE s.user_id = $1 AND s.status != 'finished' LIMIT 1`, [user.id]);
            const shift = shiftRes.rows[0];
            if (!shift) return res.json({ action: 'show_driver_menu', text: '⚠️ Смена не найдена.', user });

            if (shift.invoice_requested_at) { // Процесс финиша
                if (shift.odometer_required && !shift.photo_end_url) {
                    await client.query(`UPDATE shifts SET photo_end_url = $1 WHERE id = $2`, [photo_url, shift.id]);
                    if (user.tenant_invoice_required) {
                        await client.query(`UPDATE shifts SET status = 'pending_invoice' WHERE id = $1`, [shift.id]);
                        return res.json({ action: 'ask_photo', text: '✅ Одометр принят. Теперь пришлите фото НАКЛАДНОЙ.', user });
                    }
                    await finalizeShift(client, shift.id);
                    return res.json({ action: 'status', text: '🏁 Смена завершена!', user });
                }
                if (shift.status === 'pending_invoice') {
                    await client.query(`UPDATE shifts SET photo_invoice_url = $1 WHERE id = $2`, [photo_url, shift.id]);
                    await finalizeShift(client, shift.id);
                    return res.json({ action: 'status', text: '✅ Накладная принята! Смена закрыта.', user });
                }
            } else { // Процесс старта
                await client.query(`UPDATE shifts SET photo_start_url = $1 WHERE id = $2`, [photo_url, shift.id]);
                return res.json({ action: 'status', text: '✅ Фото одометра принято! Хорошего пути.', user });
            }
        }

        // 4. ВЫБОР МАШИНЫ / ОБЪЕКТА
        if (internalCmd === 'TRK' && paramId) {
            await client.query(`UPDATE shifts SET truck_id = $1, status = 'pending_site' WHERE user_id = $2 AND status = 'pending_truck'`, [paramId, user.id]);
            return res.json({ action: 'select_site', text: '🚚 Машина выбрана. Теперь выберите объект:', user });
        }
        if (internalCmd === 'STE' && paramId) {
            const siteInfo = await client.query(`SELECT name, odometer_required FROM dict_sites WHERE id = $1`, [paramId]);
            await client.query(`UPDATE shifts SET site_id = $1, status = 'active', start_time = NOW() WHERE user_id = $2 AND status = 'pending_site'`, [paramId, user.id]);
            const odoMsg = siteInfo.rows[0]?.odometer_required ? '\n\n📸 <b>Внимание:</b> Объект требует фото одометра. Пришлите его прямо сейчас.' : '';
            return res.json({ action: siteInfo.rows[0]?.odometer_required ? 'ask_photo' : 'status', text: `🚀 Смена открыта на объекте ${siteInfo.rows[0].name}!${odoMsg}`, user });
        }

        // 5. ЗАВЕРШЕНИЕ / ОТМЕНА
        if (internalCmd === 'CANCEL_SHIFT') {
            await client.query(`DELETE FROM shifts WHERE user_id = $1 AND status IN ('pending_truck', 'pending_site')`, [user.id]);
            return res.json({ action: 'show_driver_menu', text: '❌ Черновик удален.', user });
        }

        if (internalCmd === 'END_SHIFT' || internalCmd === 'END_SHIFT_NOW' || (rawText && !rawText.startsWith('/') && !rawText.includes('{'))) {
            const shiftRes = await client.query(`SELECT s.*, st.odometer_required FROM shifts s LEFT JOIN dict_sites st ON s.site_id = st.id WHERE s.user_id = $1 AND s.status = 'active' LIMIT 1`, [user.id]);
            const shift = shiftRes.rows[0];
            
            if (!shift) {
                const draft = await client.query(`SELECT status FROM shifts WHERE user_id = $1 AND status != 'finished' LIMIT 1`, [user.id]);
                if (draft.rows.length > 0) return res.json({ action: 'status', text: '⚠️ У вас не завершено оформление смены. Продолжите выбор или отмените черновик.', user });
                return res.json({ action: 'show_driver_menu', text: '❌ Активной смены нет.', user });
            }

            await client.query(`UPDATE shifts SET invoice_requested_at = NOW() WHERE id = $1`, [shift.id]);
            if (!rawText.startsWith('/') && !rawText.includes('{')) await client.query(`UPDATE shifts SET comment = $1 WHERE id = $2`, [rawText, shift.id]);
            
            if (shift.odometer_required && !shift.photo_end_url) return res.json({ action: 'ask_photo', text: '📸 Пришлите фото одометра (финиш).', user });
            if (user.tenant_invoice_required) {
                await client.query(`UPDATE shifts SET status = 'pending_invoice' WHERE id = $1`, [shift.id]);
                return res.json({ action: 'ask_photo', text: '🏁 Пришлите фото НАКЛАДНОЙ.', user });
            }
            await finalizeShift(client, shift.id);
            return res.json({ action: 'status', text: '🏁 Смена закрыта!', user });
        }

        // 6. РОУТИНГ
        let action = 'show_driver_menu';
        let respText = 'Выберите действие:';

        if (internalCmd === 'START_SHIFT') {
            const cur = await client.query(`SELECT id FROM shifts WHERE user_id = $1 AND status != 'finished' LIMIT 1`, [user.id]);
            if (cur.rows.length > 0) return res.json({ action: 'status', text: '⚠️ У вас уже есть открытая смена или черновик.', user });
            await client.query(`INSERT INTO shifts (user_id, tenant_id, status) VALUES ($1, $2, 'pending_truck')`, [user.id, user.tenant_id]);
            action = 'start_shift';
        } else if (internalCmd === 'STATUS') action = 'status';
        else if (internalCmd === 'DRIVER') action = 'show_driver_menu';
        else if (internalCmd === 'ADMIN' && user.role === 'admin') action = 'show_admin_menu';

        return res.json({ action, text: respText, user });

    } catch (e) { console.error(e); res.status(500).json({ error: 'Server Error' }); }
    finally { client.release(); }
});

app.listen(PORT, () => console.log(`API on ${PORT}`));
