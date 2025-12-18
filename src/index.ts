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

// 1. LOGIN (С Логами "Шпиона")
app.post('/api/auth/login', async (req, res) => {
  const { login, password } = req.body;
  console.log(`[LOGIN ATTEMPT] Логин: '${login}', Пароль: '${password}'`);

  try {
    // Используем pool.query вместо query
    const result = await pool.query('SELECT * FROM public.users WHERE login = $1', [login]);
    
    if (result.rows.length === 0) {
        console.log('[LOGIN ERROR] Пользователь не найден в базе данных!');
        return res.status(401).json({ error: 'User not found' });
    }

    const user = result.rows[0];
    console.log(`[LOGIN INFO] Нашел пользователя ID: ${user.id}, Хеш в базе: ${user.password_hash}`);

    // Проверка пароля
    const validPassword = await bcrypt.compare(password, user.password_hash);
    
    console.log(`[LOGIN CHECK] Результат проверки пароля: ${validPassword}`);

    if (!validPassword) {
        // Временный хак: если хеш сложный, а пароль простой, можно раскомментировать строку ниже для генерации нового хеша в консоль
        const newHash = await bcrypt.hash(password, 10);
        console.log(`[NEW HASH FOR DB] Если пароль верный, обнови хеш в БД на: ${newHash}`);
        return res.status(401).json({ error: 'Invalid password' });
    }

    const token = jwt.sign(
      { id: user.id, role: user.role, tenant_id: user.tenant_id },
      JWT_SECRET,
      { expiresIn: '12h' }
    );

    res.json({ token, user: { id: user.id, full_name: user.full_name, role: user.role } });
  } catch (err) {
    console.error('[LOGIN CRITICAL]', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// 2. DASHBOARD STATS
app.get('/api/dashboard/stats', authenticateToken, async (req: AuthRequest, res) => {
  try {
    const tId = req.user.tenant_id;
    const shifts = await pool.query("SELECT COUNT(*) FROM shifts WHERE tenant_id = $1 AND status = 'active'", [tId]);
    const drivers = await pool.query("SELECT COUNT(*) FROM users WHERE tenant_id = $1 AND role = 'driver' AND is_active = true", [tId]);
    res.json({ activeShifts: parseInt(shifts.rows[0].count), activeDrivers: parseInt(drivers.rows[0].count) });
  } catch (err) { res.status(500).send('Error'); }
});

// 3. GET SHIFTS
app.get('/api/shifts', authenticateToken, async (req: AuthRequest, res) => {
  try {
    const sql = `SELECT s.*, u.full_name as driver_name FROM shifts s LEFT JOIN users u ON s.user_id = u.id WHERE s.tenant_id = $1 ORDER BY s.created_at DESC LIMIT 50`;
    const result = await pool.query(sql, [req.user.tenant_id]);
    res.json(result.rows);
  } catch (err) { res.status(500).send('Error'); }
});

app.listen(PORT, () => console.log(`Server on ${PORT}`));
