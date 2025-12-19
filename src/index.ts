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

// --- MIDDLEWARE (Обновленный) ---
interface AuthRequest extends Request { user?: any; }

const authenticateToken = async (req: AuthRequest, res: Response, next: NextFunction) => {
  // 1. Сначала проверяем API Key (для n8n)
  const apiKey = req.headers['x-api-key'] as string;
  if (apiKey) {
    try {
      const result = await pool.query('SELECT id FROM tenants WHERE api_key = $1', [apiKey]);
      if (result.rows.length > 0) {
        // Если ключ верный, мы даем права "Системы"
        req.user = { 
          id: 0, // Системный ID (нет конкретного юзера)
          role: 'system', 
          tenant_id: result.rows[0].id 
        };
        return next();
      } else {
        return res.status(403).json({ error: 'Invalid API Key' });
      }
    } catch (e) {
      console.error(e);
      return res.sendStatus(500);
    }
  }

  // 2. Если ключа нет, проверяем JWT (для фронтенда)
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, (err: any, user: any) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// --- ROUTES ---

// AUTH
app.post('/api/auth/login', async (req, res) => {
  const { login, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM public.users WHERE login = $1', [login]);
    if (result.rows.length === 0) return res.status(401).json({ error: 'User not found' });

    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password, user.password_hash);
    
    if (!validPassword) return res.status(401).json({ error: 'Invalid password' });

    const token = jwt.sign(
      { id: user.id, role: user.role, tenant_id: user.tenant_id },
      JWT_SECRET,
      { expiresIn: '12h' }
    );
    res.json({ token, user: { id: user.id, full_name: user.full_name, role: user.role } });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Server error' }); }
});

// GET DATA
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
    // Если это n8n, он должен передать user_id как query param: ?user_id=123
    const targetUserId = req.user.role === 'system' ? req.query.user_id : req.user.id;
    
    if (!targetUserId) return res.status(400).json({ error: 'user_id required for system' });

    try {
        const result = await pool.query("SELECT * FROM shifts WHERE user_id = $1 AND status = 'active' LIMIT 1", [targetUserId]);
        res.json(result.rows[0] || null);
    } catch (err) { res.status(500).send('Error'); }
});

// --- WRITE OPERATIONS (START / END) ---

app.post('/api/shifts/start', authenticateToken, async (req: AuthRequest, res) => {
    const { truck_id, site_id } = req.body;
    
    // ВАЖНО: Определяем, кто водитель.
    // Если это система (n8n), то user_id должен прийти в body.
    // Если это живой водитель, берем из токена.
    let user_id = req.user.id;
    if (req.user.role === 'system') {
        user_id = req.body.user_id;
        if (!user_id) return res.status(400).json({ error: 'user_id is required for system requests' });
    }

    const tenant_id = req.user.tenant_id;

    try {
        const activeCheck = await pool.query("SELECT id FROM shifts WHERE user_id = $1 AND status = 'active'", [user_id]);
        if (activeCheck.rows.length > 0) return res.status(400).json({ error: 'У этого водителя уже есть активная смена' });

        const result = await pool.query(
            "INSERT INTO shifts (user_id, tenant_id, truck_id, site_id, start_time, status) VALUES ($1, $2, $3, $4, NOW(), 'active') RETURNING *",
            [user_id, tenant_id, truck_id, site_id]
        );
        res.json(result.rows[0]);
    } catch (err) { console.error(err); res.status(500).send('Error'); }
});

app.post('/api/shifts/end', authenticateToken, async (req: AuthRequest, res) => {
    let user_id = req.user.id;
    if (req.user.role === 'system') {
        user_id = req.body.user_id;
        if (!user_id) return res.status(400).json({ error: 'user_id is required for system requests' });
    }

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
