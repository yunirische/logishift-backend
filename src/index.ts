import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import { Pool } from 'pg';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';

dotenv.config();

// --- CONFIG ---
const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'secret';
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

app.use(cors());
app.use(express.json());

// --- MIDDLEWARE ---
interface AuthRequest extends Request { user?: any; }
const authenticateToken = (req: AuthRequest, res: Response, next: NextFunction) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, JWT_SECRET, (err: any, user: any) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// --- ROUTES ---

// AUTH (С ЛОГАМИ!)
app.post('/api/auth/login', async (req, res) => {
  const { login, password } = req.body;
  console.log(`[DEBUG] Попытка входа. Логин: '${login}', Пароль: '${password}'`);

  try {
    const result = await pool.query('SELECT * FROM public.users WHERE login = $1', [login]);
    
    if (result.rows.length === 0) {
        console.log(`[DEBUG] ОШИБКА: Пользователь с логином '${login}' не найден в БД.`);
        // Поможем найти ошибку: выведем всех юзеров, какие есть
        const allUsers = await pool.query('SELECT login FROM public.users');
        console.log(`[DEBUG] Доступные логины в базе: ${allUsers.rows.map(u => u.login).join(', ')}`);
        return res.status(401).json({ error: 'User not found' });
    }

    const user = result.rows[0];
    console.log(`[DEBUG] Юзер найден (ID: ${user.id}). Сравниваю хеши...`);

    const validPassword = await bcrypt.compare(password, user.password_hash);
    
    console.log(`[DEBUG] Результат проверки пароля: ${validPassword}`);

    if (!validPassword) return res.status(401).json({ error: 'Invalid password' });

    const token = jwt.sign(
      { id: user.id, role: user.role, tenant_id: user.tenant_id },
      JWT_SECRET,
      { expiresIn: '12h' }
    );
    res.json({ token, user: { id: user.id, full_name: user.full_name, role: user.role } });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Server error' }); }
});

// READ DATA
app.get('/api/dashboard/stats', authenticateToken, async (req: AuthRequest, res) => {
  try {
    const tId = req.user.tenant_id;
    const shifts = await pool.query("SELECT COUNT(*) FROM shifts WHERE tenant_id = $1 AND status = 'active'", [tId]);
    const drivers = await pool.query("SELECT COUNT(*) FROM users WHERE tenant_id = $1 AND role = 'driver' AND is_active = true", [tId]);
    res.json({ activeShifts: parseInt(shifts.rows[0].count), activeDrivers: parseInt(drivers.rows[0].count) });
  } catch (err) { res.status(500).send('Error'); }
});

app.get('/api/shifts', authenticateToken, async (req: AuthRequest, res) => {
  try {
    const sql = `SELECT s.*, u.full_name as driver_name, t.name as truck_name, st.name as site_name 
                 FROM shifts s 
                 LEFT JOIN users u ON s.user_id = u.id 
                 LEFT JOIN dict_trucks t ON s.truck_id = t.id
                 LEFT JOIN dict_sites st ON s.site_id = st.id
                 WHERE s.tenant_id = $1 ORDER BY s.created_at DESC LIMIT 50`;
    const result = await pool.query(sql, [req.user.tenant_id]);
    res.json(result.rows);
  } catch (err) { res.status(500).send('Error'); }
});

app.get('/api/trucks', authenticateToken, async (req: AuthRequest, res) => {
    try {
        const result = await pool.query('SELECT * FROM dict_trucks WHERE tenant_id = $1 AND is_active = true ORDER BY name', [req.user.tenant_id]);
        res.json(result.rows);
    } catch (err) { res.status(500).send('Error'); }
});

app.get('/api/sites', authenticateToken, async (req: AuthRequest, res) => {
    try {
        const result = await pool.query('SELECT * FROM dict_sites WHERE tenant_id = $1 AND is_active = true ORDER BY name', [req.user.tenant_id]);
        res.json(result.rows);
    } catch (err) { res.status(500).send('Error'); }
});

app.get('/api/shifts/current', authenticateToken, async (req: AuthRequest, res) => {
    try {
        const result = await pool.query("SELECT * FROM shifts WHERE user_id = $1 AND status = 'active' LIMIT 1", [req.user.id]);
        res.json(result.rows[0] || null);
    } catch (err) { res.status(500).send('Error'); }
});

// WRITE OPERATIONS
app.post('/api/shifts/start', authenticateToken, async (req: AuthRequest, res) => {
    const { truck_id, site_id } = req.body;
    const user_id = req.user.id;
    const tenant_id = req.user.tenant_id;

    try {
        const activeCheck = await pool.query("SELECT id FROM shifts WHERE user_id = $1 AND status = 'active'", [user_id]);
        if (activeCheck.rows.length > 0) return res.status(400).json({ error: 'У вас уже есть активная смена' });

        const result = await pool.query(
            "INSERT INTO shifts (user_id, tenant_id, truck_id, site_id, start_time, status) VALUES ($1, $2, $3, $4, NOW(), 'active') RETURNING *",
            [user_id, tenant_id, truck_id, site_id]
        );
        res.json(result.rows[0]);
    } catch (err) { console.error(err); res.status(500).send('Error'); }
});

app.post('/api/shifts/end', authenticateToken, async (req: AuthRequest, res) => {
    const user_id = req.user.id;
    try {
        const result = await pool.query(
            "UPDATE shifts SET end_time = NOW(), status = 'finished' WHERE user_id = $1 AND status = 'active' RETURNING *",
            [user_id]
        );
        if (result.rows.length === 0) return res.status(404).json({ error: 'Нет активной смены' });
        res.json(result.rows[0]);
    } catch (err) { console.error(err); res.status(500).send('Error'); }
});

app.listen(PORT, () => console.log(`Server on ${PORT}`));
