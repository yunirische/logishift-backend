import express, { Request, Response, NextFunction } from 'express';
import { PrismaClient } from '@prisma/client';
import path from 'path';
import fs from 'fs/promises';
import { existsSync } from 'fs';
import dotenv from 'dotenv';
import cors from 'cors';
import axios from 'axios';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

dotenv.config();

// --- 1. ГЛОБАЛЬНЫЕ ПАТЧИ ---
(BigInt.prototype as any).toJSON = function () {
  return this.toString();
};

// --- 2. ИНИЦИАЛИЗАЦИЯ ---
const prisma = new PrismaClient();
const app = express();
const PORT = process.env.PORT || 3000;
const UPLOAD_DIR = process.env.UPLOAD_DIR || './uploads';
const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-key';
const TG_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;

app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(UPLOAD_DIR));

// Интерфейс для расширения Request
interface AuthRequest extends Request {
  user?: { id: number; tenant_id: number; role: string };
}

// --- 3. UTILS ---
const parseId = (id: any): number => {
  const parsed = parseInt(id);
  if (isNaN(parsed)) throw new Error('Invalid ID format');
  return parsed;
};

const formatInTimezone = (date: Date | null, timezone: string = 'Europe/Moscow'): string => {
  if (!date) return '--:--';
  return date.toLocaleString('ru-RU', {
    timeZone: timezone,
    hour: '2-digit', minute: '2-digit', day: '2-digit', month: '2-digit'
  });
};

const authenticateJWT = (req: AuthRequest, res: Response, next: NextFunction) => {
  const authHeader = req.headers.authorization;
  if (authHeader) {
    const token = authHeader.split(' ')[1];
    jwt.verify(token, JWT_SECRET, (err: any, user: any) => {
      if (err) return res.sendStatus(403);
      req.user = user;
      next();
    });
  } else {
    res.sendStatus(401);
  }
};

// --- 4. SERVICES ---

class MediaService {
  async downloadAndSave(fileId: string, tenantId: number): Promise<string> {
    if (!TG_BOT_TOKEN) throw new Error('TG_BOT_TOKEN missing');
    const { data: fileData } = await axios.get(`https://api.telegram.org/bot${TG_BOT_TOKEN}/getFile?file_id=${fileId}`);
    const filePath = fileData.result.file_path;
    const now = new Date();
    const relativeDir = path.join(tenantId.toString(), now.getFullYear().toString(), (now.getMonth() + 1).toString().padStart(2, '0'));
    const absoluteDir = path.join(UPLOAD_DIR, relativeDir);
    if (!existsSync(absoluteDir)) await fs.mkdir(absoluteDir, { recursive: true });
    const fileName = `${Date.now()}-${path.basename(filePath)}`;
    const response = await axios({ method: 'GET', url: `https://api.telegram.org/file/bot${TG_BOT_TOKEN}/${filePath}`, responseType: 'arraybuffer' });
    await fs.writeFile(path.join(absoluteDir, fileName), response.data);
    return path.join(relativeDir, fileName);
  }
}

const mediaService = new MediaService();

class ShiftService {
  async startShiftDraft(userId: number) {
    await prisma.users.update({ where: { id: userId }, data: { current_state: 'pending_truck' } });
  }

  async selectTruck(userId: number, truckId: number) {
    return await prisma.$transaction(async (tx) => {
      const truck = await tx.dict_trucks.findUnique({ where: { id: truckId } });
      if (!truck || truck.is_busy || !truck.is_active) throw new Error('Машина занята или недоступна');
      await tx.dict_trucks.update({ where: { id: truckId }, data: { is_busy: true } });
      await tx.shifts.create({ data: { user_id: userId, tenant_id: truck.tenant_id!, truck_id: truckId, status: 'pending_site' } });
      await tx.users.update({ where: { id: userId }, data: { current_state: 'pending_site' } });
    });
  }

  async selectSite(userId: number, siteId: number) {
    return await prisma.$transaction(async (tx) => {
      const site = await tx.dict_sites.findUnique({ where: { id: siteId } });
      const shift = await tx.shifts.findFirst({ where: { user_id: userId, status: 'pending_site' }, orderBy: { id: 'desc' } });
      if (!site || !shift) throw new Error('Ошибка контекста');
      const next = site.odometer_required ? 'awaiting_odo_start' : 'active';
      await tx.shifts.update({ where: { id: shift.id }, data: { site_id: siteId, status: next, start_time: next === 'active' ? new Date() : null } });
      await tx.users.update({ where: { id: userId }, data: { current_state: next } });
      return { odometerRequired: site.odometer_required };
    });
  }

  async cancelShift(userId: number) {
    await prisma.$transaction(async (tx) => {
      const shift = await tx.shifts.findFirst({ where: { user_id: userId, status: { not: 'finished' } }, orderBy: { id: 'desc' } });
      if (shift?.truck_id) await tx.dict_trucks.update({ where: { id: shift.truck_id }, data: { is_busy: false } });
      if (shift) await tx.shifts.delete({ where: { id: shift.id } });
      await tx.users.update({ where: { id: userId }, data: { current_state: 'idle' } });
    });
  }

  async requestEndShift(userId: number) {
    return await prisma.$transaction(async (tx) => {
      const shift = await tx.shifts.findFirst({ where: { user_id: userId, status: 'active' }, include: { site: true, tenant: true } });
      if (!shift) throw new Error('Активная смена не найдена');
      let next = shift.site?.odometer_required ? 'awaiting_odo_end' : (shift.tenant.invoice_required || shift.site?.invoice_required ? 'awaiting_invoice' : 'finished');
      if (next === 'finished') return await this.finalizeShiftInternal(tx, shift.id);
      await tx.shifts.update({ where: { id: shift.id }, data: { status: next } });
      await tx.users.update({ where: { id: userId }, data: { current_state: next } });
      return { message: next === 'awaiting_odo_end' ? "📸 Пришлите фото одометра (ФИНИШ):" : "📸 Пришлите фото НАКЛАДНОЙ:" };
    });
  }

  async handleShiftPhoto(userId: number, fileId: string) {
    const user = await prisma.users.findUnique({ where: { id: userId }, include: { tenant: true } });
    if (!user) throw new Error('User not found');
    const photoUrl = await mediaService.downloadAndSave(fileId, user.tenant_id!);
    return await prisma.$transaction(async (tx) => {
      const shift = await tx.shifts.findFirst({ where: { user_id: userId, status: { not: 'finished' } }, include: { site: true }, orderBy: { id: 'desc' } });
      if (!shift) throw new Error('Смена не найдена');
      if (user.current_state === 'awaiting_odo_start') {
        await tx.shifts.update({ where: { id: shift.id }, data: { photo_start_url: photoUrl, status: 'active', start_time: new Date() } });
        await tx.users.update({ where: { id: userId }, data: { current_state: 'active' } });
        return { message: "✅ Одометр принят. Смена открыта!" };
      }
      if (user.current_state === 'awaiting_odo_end') {
        await tx.shifts.update({ where: { id: shift.id }, data: { photo_end_url: photoUrl } });
        if (user.tenant.invoice_required || shift.site?.invoice_required) {
          await tx.shifts.update({ where: { id: shift.id }, data: { status: 'awaiting_invoice' } });
          await tx.users.update({ where: { id: userId }, data: { current_state: 'awaiting_invoice' } });
          return { message: "📸 Одометр принят. Теперь фото НАКЛАДНОЙ:" };
        }
        return await this.finalizeShiftInternal(tx, shift.id);
      }
      if (user.current_state === 'awaiting_invoice') {
        await tx.shifts.update({ where: { id: shift.id }, data: { photo_invoice_url: photoUrl } });
        return await this.finalizeShiftInternal(tx, shift.id);
      }
      throw new Error('Некорректное состояние');
    });
  }

  private async finalizeShiftInternal(tx: any, shiftId: number) {
    const shift = await tx.shifts.findUnique({ where: { id: shiftId }, include: { user: true } });
    const endTime = new Date();
    const diff = endTime.getTime() - (shift!.start_time?.getTime() || endTime.getTime());
    const hours = Number((diff / (1000 * 60 * 60)).toFixed(2));
    const salary = hours * Number(shift!.user.hourly_rate || 0);
    await tx.shifts.update({ where: { id: shiftId }, data: { status: 'finished', end_time: endTime, hours_worked: hours, salary: salary } });
    await tx.dict_trucks.update({ where: { id: shift!.truck_id! }, data: { is_busy: false } });
    await tx.users.update({ where: { id: shift!.user_id }, data: { current_state: 'idle' } });
    return { message: "🏁 Смена успешно завершена!" };
  }
}

const shiftService = new ShiftService();

// --- 5. GATEWAY CONTROLLER ---

const GatewayController = {
  async handleWebhook(req: Request, res: Response) {
    // Извлекаем данные, страхуемся от пустых значений
    const { user_id, type, payload } = req.body;
    if (!user_id) return res.status(400).json({ error: "Missing user_id" });

    try {
      const user = await prisma.users.findUnique({ 
        where: { tg_user_id: BigInt(user_id) }, 
        include: { tenant: true } 
      });

      if (!user) {
        return res.json(GatewayController.formatResponse("⚠️ Вы не зарегистрированы в системе. Обратитесь к администратору."));
      }

      const activeShift = await prisma.shifts.findFirst({ 
        where: { user_id: user.id, status: { not: 'finished' } } 
      });

      let result: any;

      if (type === 'callback') {
        result = await GatewayController.processCallback(user, payload.data);
      } else if (type === 'text') {
        result = await GatewayController.processText(user, payload.text, activeShift);
      } else if (type === 'photo') {
        result = await shiftService.handleShiftPhoto(user.id, payload.file_id);
      }

      const timeStr = formatInTimezone(new Date(), user.tenant?.timezone);
      
      // Формируем чистый ответ
      return res.json(GatewayController.formatResponse(
        `${result?.message || "Меню:"}\n\n🕒 ${timeStr}`,
        result?.buttons || [],
        user.current_state,
        activeShift?.id,
        user.id,
        user.last_menu_message_id?.toString() // Превращаем BigInt в строку для n8n
      ));

    } catch (e: any) {
      console.error('GATEWAY ERROR:', e);
      // В случае ошибки возвращаем безопасный ответ, чтобы n8n не зациклился
      return res.json({
        ui: { method: "sendMessage", text: `❌ Ошибка сервера: ${e.message}`, buttons: [], delete_original: false },
        state: { current_step: "error", active_shift_id: null }
      });
    }
  },

  async processCallback(user: any, data: string) {
    if (data === 'START_SHIFT') {
      await shiftService.startShiftDraft(user.id);
      const trucks = await prisma.dict_trucks.findMany({ where: { tenant_id: user.tenant_id, is_active: true, is_busy: false } });
      return { message: "🚚 Выберите машину:", buttons: trucks.map(t => [{ text: t.name, callback_data: `TRK_${t.id}` }]) };
    }
    if (data.startsWith('TRK_')) {
      await shiftService.selectTruck(user.id, parseId(data.split('_')[1]));
      const sites = await prisma.dict_sites.findMany({ where: { tenant_id: user.tenant_id, is_active: true } });
      return { message: "📍 Теперь объект:", buttons: sites.map(s => [{ text: s.name, callback_data: `STE_${s.id}` }]) };
    }
    if (data.startsWith('STE_')) {
      const res = await shiftService.selectSite(user.id, parseId(data.split('_')[1]));
      return { message: res.odometerRequired ? "📸 Пришлите фото одометра (СТАРТ):" : "🚀 Смена открыта!", buttons: res.odometerRequired ? [] : [[{ text: "🏁 Завершить", callback_data: "END_SHIFT" }]] };
    }
    if (data === 'END_SHIFT') return await shiftService.requestEndShift(user.id);
    if (data === 'CANCEL') { await shiftService.cancelShift(user.id); return { message: "❌ Отменено." }; }
    return { message: "Меню:" };
  },

  async processText(user: any, text: string, activeShift: any) {
    const t = text.trim().toLowerCase();
    if (t === '/start' || t === 'меню') return { message: `Привет, ${user.full_name}!`, buttons: [[{ text: "🚀 Начать смену", callback_data: "START_SHIFT" }]] };
    if (user.current_state === 'active' && activeShift) {
      await prisma.shifts.update({ where: { id: activeShift.id }, data: { comment: text } });
      return { message: "✅ Комментарий обновлен." };
    }
    return { message: "Используйте меню." };
  },

  formatResponse(text: string, buttons: any[] = [], state: string = 'idle', shiftId?: number, userInternalId?: number, lastMenuId?: string) {
    return {
      ui: { 
        method: "sendMessage", 
        text, 
        buttons, 
        // Если есть ID старого меню, даем команду n8n его удалить
        delete_original: !!lastMenuId 
      },
      state: { 
        current_step: state, 
        active_shift_id: shiftId || null, 
        user_internal_id: userInternalId || null, 
        last_menu_message_id: lastMenuId || null 
      }
    };
  }
};

// --- 6. ROUTES ---
const api = express.Router();

api.post('/gateway', GatewayController.handleWebhook);

// Эндпоинт для n8n: сохранить ID сообщения, которое бот только что отправил
api.post('/users/set-menu-id', async (req, res) => {
  try {
    const { user_id, message_id } = req.body;
    await prisma.users.update({ 
      where: { id: parseId(user_id) }, 
      data: { last_menu_message_id: BigInt(message_id) } 
    });
    res.json({ success: true });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

api.post('/auth/onboard', async (req, res) => {
  try {
    const { company_name, admin_name, email, password, timezone, tg_user_id } = req.body;
    const hash = await bcrypt.hash(password, 10);
    const plan = await prisma.plans.findFirst({ where: { code: 'free' } });
    const result = await prisma.$transaction(async (tx) => {
      const tenant = await tx.tenants.create({ data: { name: company_name, plan_id: plan!.id, timezone: timezone || 'Europe/Moscow' } });
      const user = await tx.users.create({ data: { tenant_id: tenant.id, role: 'admin', full_name: admin_name, email, password_hash: hash, tg_user_id: tg_user_id ? BigInt(tg_user_id) : null, current_state: 'idle' } });
      return { tenant, user };
    });
    res.json(result);
  } catch (e: any) { res.status(500).json({ error: e.message }); }
});

api.get('/admin/stats', authenticateJWT, async (req: AuthRequest, res: Response) => {
  try {
    const tid = req.user!.tenant_id;
    const [active, trucks, photos] = await Promise.all([
      prisma.shifts.count({ where: { tenant_id: tid, status: { not: 'finished' } } }),
      prisma.dict_trucks.count({ where: { tenant_id: tid, is_busy: true } }),
      prisma.shifts.count({ where: { tenant_id: tid, updated_at: { gte: new Date(Date.now() - 86400000) } } })
    ]);
    res.json({ activeShifts: active, busyTrucks: trucks, photos24h: photos });
  } catch (e: any) { res.status(500).json({ error: e.message }); }
});

app.use('/api/v1', api);

app.listen(PORT, () => console.log(`🚀 Server ready on port ${PORT}`));
