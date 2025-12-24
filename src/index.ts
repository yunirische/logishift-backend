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
const UPLOAD_DIR = process.env.UPLOAD_DIR || '/app/uploads';

// --- БЛОК 1: ПОДКЛЮЧЕНИЕ К БАЗЕ ДАННЫХ ---
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

// --- БЛОК 2: НАСТРОЙКА ЗАГРУЗКИ ФАЙЛОВ (MULTER) ---
if (!fs.existsSync(UPLOAD_DIR)) {
    fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOAD_DIR),
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + path.extname(file.originalname));
    }
});
const upload = multer({ storage: storage });

app.use(cors());
app.use(express.json());

// --- БЛОК 3: ЗАЩИТА (MIDDLEWARE) ---
// Проверяет либо API Key (от n8n), либо Token (от фронтенда)
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
// n8n скачивает фото из ТГ и отправляет сюда
app.post('/api/upload', authenticateToken, upload.single('file'), (req: any, res: Response) => {
    if (!req.file) return res.status(400).json({ error: 'Файл не загружен' });
    res.json({ url: `/uploads/${req.file.filename}` });
});

// --- БЛОК 5: ЛОГИКА СМЕН (SHIFTS) ---

// 5.1 Получить текущую смену (активную или черновик)
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
    res.json(result.rows[0] || null);
});

// 5.2 Сохранить ID сообщения меню (Чистый чат)
app.post('/api/users/set-menu-id', authenticateToken, async (req: AuthRequest, res: Response) => {
    const { message_id, user_id: bodyUserId } = req.body;
    const userId = req.user.role === 'system' ? bodyUserId : req.user.id;
    await pool.query('UPDATE users SET last_menu_message_id = $1 WHERE id = $2', [message_id, userId]);
    res.json({ success: true });
});

// --- БЛОК 6: ГЛАВНЫЙ ОБРАБОТЧИК (WEBHOOK ДЛЯ N8N) ---
app.post('/api/integrations/telegram/webhook', async (req: Request, res: Response) => {
    const { id: tgId, text, photo_url, mileage } = req.body;
    const client = await pool.connect();

    try {
        // 1. Ищем пользователя
        const userRes = await client.query(`
            SELECT u.*, t.timezone, t.invoice_required 
            FROM users u LEFT JOIN tenants t ON u.tenant_id = t.id
            WHERE u.telegram_user_id = $1`, [tgId]);
        
        if (userRes.rows.length === 0) return res.json({ action: 'ask_invite', text: 'Вы не зарегистрированы.' });
        const user = userRes.rows[0];
        await client.query(`SELECT set_config('audit.user_id', $1, true)`, [user.id.toString()]);

        const cmd = (text || '').split(' ')[0];

        // --- ЛОГИКА: ОБРАБОТКА ЗАГРУЖЕННОГО ФОТО ---
        if (text === 'PHOTO_UPLOADED') {
            const shiftRes = await client.query(`SELECT * FROM shifts WHERE user_id = $1 AND status != 'finished' LIMIT 1`, [user.id]);
            const shift = shiftRes.rows[0];
            if (!shift) return res.json({ action: 'show_driver_menu', text: 'Смена не найдена.' });

            if (shift.status === 'pending_invoice') {
                // Это фото накладной -> Закрываем смену
                await client.query(`UPDATE shifts SET photo_end_url = $1, status = 'finished' WHERE id = $2`, [photo_url, shift.id]);
                return res.json({ action: 'status', text: '✅ Накладная принята. Смена закрыта!', user });
            } else {
                // Это фото одометра -> Просто сохраняем ссылку
                await client.query(`UPDATE shifts SET photo_start_url = $1 WHERE id = $2`, [photo_url, shift.id]);
                return res.json({ action: 'status', text: '📸 Фото одометра сохранено.', user });
            }
        }

        // --- ЛОГИКА: ВЫБОР МАШИНЫ ---
        const truckMatch = cmd.match(/\/select_truck_(\d+)/);
        if (truckMatch) {
            await client.query(`UPDATE shifts SET truck_id = $1, status = 'pending_site' WHERE user_id = $2 AND status = 'pending_truck'`, [truckMatch[1], user.id]);
            return res.json({ action: 'select_site', text: 'Машина выбрана. Теперь укажите объект:', user });
        }

        // --- ЛОГИКА: ВЫБОР ОБЪЕКТА + ПРОВЕРКА ОДОМЕТРА ---
        const siteMatch = cmd.match(/\/select_site_(\d+)/);
        if (siteMatch) {
            const siteId = siteMatch[1];
            const siteInfo = await client.query(`SELECT odometer_required FROM dict_sites WHERE id = $1`, [siteId]);
            
            await client.query(`UPDATE shifts SET site_id = $1, status = 'active', start_time = NOW() WHERE user_id = $2 AND status = 'pending_site'`, [siteId, user.id]);
            
            // Если объект требует одометр — просим фото
            if (siteInfo.rows[0]?.odometer_required) {
                return res.json({ action: 'ask_photo', text: '📸 Объект требует фото одометра. Пришлите его сейчас.', user });
            }
            return res.json({ action: 'status', text: '🚀 Смена открыта!', user });
        }

        // --- ЛОГИКА: ЗАВЕРШЕНИЕ СМЕНЫ ---
        if (cmd === '/end_shift_now' || (text && !text.startsWith('/'))) {
            const comment = text.startsWith('/') ? null : text;
            const updateRes = await client.query(
                `UPDATE shifts SET end_time = NOW(), status = 'pending_invoice', comment = $1 
                 WHERE user_id = $2 AND status = 'active' RETURNING id`, [comment, user.id]);
            
            if (updateRes.rows.length > 0) {
                return res.json({ action: 'status', text: '✅ Смена зафиксирована. Ждем фото накладной.', user });
            }
        }

        // --- СТАНДАРТНЫЙ РОУТИНГ ---
        let action = 'show_driver_menu';
        if (cmd === '/start_shift') {
            const hasShift = await client.query(`SELECT id FROM shifts WHERE user_id = $1 AND status != 'finished'`, [user.id]);
            if (hasShift.rows.length === 0) {
                await client.query(`INSERT INTO shifts (user_id, tenant_id, status) VALUES ($1, $2, 'pending_truck')`, [user.id, user.tenant_id]);
            }
            action = 'start_shift';
        } else if (cmd === '/status') action = 'status';
        else if (cmd === '/end_shift') action = 'end_shift';

        return res.json({ action, text: `Меню`, user });

    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Ошибка сервера' });
    } finally {
        client.release();
    }
});

app.listen(PORT, () => console.log(`Сервер запущен на порту ${PORT}`));
