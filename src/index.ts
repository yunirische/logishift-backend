import express, { Request, Response, NextFunction } from 'express';
import { PrismaClient } from '@prisma/client';
import multer from 'multer';
import path from 'path';
import fs from 'fs/promises';
import { existsSync } from 'fs';
import dotenv from 'dotenv';
import cors from 'cors';
import axios from 'axios';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
declare global {
  namespace Express {
    interface Request {
      user?: {
        id: number;
        tenant_id: number;
        role: string;
      };
    }
  }
}

dotenv.config();

// --- 1. ГЛОБАЛЬНЫЕ ПАТЧИ ---
(BigInt.prototype as any).toJSON = function () {
  return this.toString();
};

// --- 2. КОНФИГУРАЦИЯ ---
const prisma = new PrismaClient();
const app = express();
const PORT = process.env.PORT || 3000;
const UPLOAD_DIR = process.env.UPLOAD_DIR || './uploads';
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-key';
const CDN_URL = 'https://bot.kontrolsmen.ru/uploads';
const TG_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;

app.use(cors());
app.use(express.json());

// --- 3. UTILS ---
const parseId = (id: any): number => {
  const parsed = parseInt(id);
  if (isNaN(parsed)) throw new Error('Некорректный формат ID');
  return parsed;
};

const formatInTimezone = (date: Date | null, timezone: string = 'Europe/Moscow'): string => {
  if (!date) return '--:--';
  return date.toLocaleString('ru-RU', {
    timeZone: timezone,
    hour: '2-digit', minute: '2-digit', day: '2-digit', month: '2-digit'
  });
};

// Middleware для защиты админских роутов
const authenticateJWT = (req: any, res: Response, next: NextFunction) => {
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
    if (!TG_BOT_TOKEN) throw new Error('TG_BOT_TOKEN не настроен');
    
    // 1. Получаем путь
    const { data: fileData } = await axios.get(`https://api.telegram.org/bot${TG_BOT_TOKEN}/getFile?file_id=${fileId}`);
    const filePath = fileData.result.file_path;
    
    // 2. Путь на диске
    const now = new Date();
    const relativeDir = path.join(
      tenantId.toString(),
      now.getFullYear().toString(),
      (now.getMonth() + 1).toString().padStart(2, '0')
    );
    const absoluteDir = path.join(UPLOAD_DIR, relativeDir);
    
    if (!existsSync(absoluteDir)) {
      await fs.mkdir(absoluteDir, { recursive: true });
    }

    const fileName = `${Date.now()}-${path.basename(filePath)}`;
    const absolutePath = path.join(absoluteDir, fileName);
    const dbPath = path.join(relativeDir, fileName);

    // 3. Скачиваем
    const response = await axios({
      method: 'GET',
      url: `https://api.telegram.org/file/bot${TG_BOT_TOKEN}/${filePath}`,
      responseType: 'arraybuffer'
    });

    await fs.writeFile(absolutePath, response.data);
    return dbPath;
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
      if (!truck || (!truck.is_active)) throw new Error('Машина недоступна');
      if (truck.is_busy) throw new Error('Машина уже занята');

      await tx.dict_trucks.update({ where: { id: truckId }, data: { is_busy: true } });
      const shift = await tx.shifts.create({
        data: {
          user_id: userId,
          tenant_id: truck.tenant_id!,
          truck_id: truckId,
          status: 'pending_site'
        }
      });
      await tx.users.update({ where: { id: userId }, data: { current_state: 'pending_site' } });
      return shift;
    });
  }

  async selectSite(userId: number, siteId: number) {
    return await prisma.$transaction(async (tx) => {
      const site = await tx.dict_sites.findUnique({ where: { id: siteId } });
      const shift = await tx.shifts.findFirst({ where: { user_id: userId, status: 'pending_site' }, orderBy: { id: 'desc' } });
      if (!site || !shift) throw new Error('Ошибка контекста выбора объекта');

      const nextStatus = site.odometer_required ? 'awaiting_odo_start' : 'active';
      await tx.shifts.update({
        where: { id: shift.id },
        data: { 
          site_id: siteId, 
          status: nextStatus,
          start_time: nextStatus === 'active' ? new Date() : null 
        }
      });
      await tx.users.update({ where: { id: userId }, data: { current_state: nextStatus } });
      return { odometerRequired: site.odometer_required };
    });
  }

  async cancelShift(userId: number) {
    await prisma.$transaction(async (tx) => {
      const shift = await tx.shifts.findFirst({ where: { user_id: userId, status: { not: 'finished' } }, orderBy: { id: 'desc' } });
      if (shift?.truck_id) {
        await tx.dict_trucks.update({ where: { id: shift.truck_id }, data: { is_busy: false } });
        await tx.shifts.delete({ where: { id: shift.id } });
      }
      await tx.users.update({ where: { id: userId }, data: { current_state: 'idle' } });
    });
  }

  async requestEndShift(userId: number) {
    return await prisma.$transaction(async (tx) => {
      const shift = await tx.shifts.findFirst({ where: { user_id: userId, status: 'active' }, include: { site: true, tenant: true } });
      if (!shift) throw new Error('Активная смена не найдена');

      if (shift.site?.odometer_required) {
        await tx.shifts.update({ where: { id: shift.id }, data: { status: 'awaiting_odo_end' } });
        await tx.users.update({ where: { id: userId }, data: { current_state: 'awaiting_odo_end' } });
        return { message: "📸 Пришлите фото одометра (ФИНИШ):", status: 'awaiting_odo_end' };
      } 
      
      if (shift.tenant.invoice_required || shift.site?.invoice_required) {
        await tx.shifts.update({ where: { id: shift.id }, data: { status: 'awaiting_invoice' } });
        await tx.users.update({ where: { id: userId }, data: { current_state: 'awaiting_invoice' } });
        return { message: "📸 Пришлите фото НАКЛАДНОЙ:", status: 'awaiting_invoice' };
      }

      return await this.finalizeShiftInternal(tx, shift.id);
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
      
      throw new Error('Некорректное состояние для загрузки фото');
    });
  }

  private async finalizeShiftInternal(tx: any, shiftId: number) {
    const shift = await tx.shifts.findUnique({ where: { id: shiftId }, include: { user: true } });
    const endTime = new Date();
    const diff = endTime.getTime() - (shift.start_time?.getTime() || endTime.getTime());
    const hours = Number((diff / (1000 * 60 * 60)).toFixed(2));
    const salary = hours * Number(shift.user.hourly_rate || 0);

    await tx.shifts.update({ where: { id: shiftId }, data: { status: 'finished', end_time: endTime, hours_worked: hours, salary: salary } });
    await tx.dict_trucks.update({ where: { id: shift.truck_id }, data: { is_busy: false } });
    await tx.users.update({ where: { id: shift.user_id }, data: { current_state: 'idle' } });
    return { message: "🏁 Смена успешно завершена!", finished: true };
  }
}

const shiftService = new ShiftService();

// --- 5. GATEWAY CONTROLLER ---

const GatewayController = {
  async handleWebhook(req: Request, res: Response) {
    const { user_id, type, payload } = req.body;
    try {
      const user = await prisma.users.findUnique({ where: { tg_user_id: BigInt(user_id) }, include: { tenant: true } });
      if (!user) return res.json(GatewayController.formatResponse("⚠️ Вы не зарегистрированы в системе."));

      const activeShift = await prisma.shifts.findFirst({ where: { user_id: user.id, status: { not: 'finished' } } });
      let result: any;

      if (type === 'callback') {
        result = await GatewayController.processCallback(user, payload.data);
      } else if (type === 'text') {
        result = await GatewayController.processText(user, payload.text, activeShift);
      } else if (type === 'photo') {
        result = await shiftService.handleShiftPhoto(user.id, payload.file_id);
      }

      const timeStr = formatInTimezone(new Date(), user.tenant?.timezone);
      return res.json(GatewayController.formatResponse(
        `${result?.message || "Выберите действие:"}\n\n🕒 ${timeStr}`,
        result?.buttons || [],
        user.current_state,
        activeShift?.id,
        true
      ));
    } catch (e: any) {
      console.error(e);
      return res.json(GatewayController.formatResponse(`⚠️ Ошибка: ${e.message}`, [], "error"));
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
      return { message: "📍 Теперь выберите объект:", buttons: sites.map(s => [{ text: s.name, callback_data: `STE_${s.id}` }]) };
    }
    if (data.startsWith('STE_')) {
      const res = await shiftService.selectSite(user.id, parseId(data.split('_')[1]));
      return { message: res.odometerRequired ? "📸 Пришлите фото одометра (СТАРТ):" : "🚀 Смена открыта! Работайте.", buttons: [] };
    }
    if (data === 'END_SHIFT') return await shiftService.requestEndShift(user.id);
    if (data === 'CANCEL') {
      await shiftService.cancelShift(user.id);
      return { message: "❌ Процесс отменен." };
    }
  },

  async processText(user: any, text: string, activeShift: any) {
    if (user.current_state === 'active' && activeShift) {
      await prisma.shifts.update({ where: { id: activeShift.id }, data: { comment: text } });
      return { message: "✅ Комментарий к смене обновлен." };
    }
    return { message: "Не понимаю вас. Используйте кнопки меню." };
  },

  formatResponse(text: string, buttons: any[] = [], state: string = 'idle', shiftId?: number, deleteOrig: boolean = false) {
    return {
      ui: { method: "sendMessage", text, buttons, delete_original: deleteOrig },
      state: { current_step: state, active_shift_id: shiftId || null }
    };
  }
};

// --- 6. ROUTES ---

app.post('/api/v1/gateway', GatewayController.handleWebhook);

// Регистрация админа
app.post('/api/v1/auth/onboard', async (req, res) => {
  try {
    const { company_name, admin_name, email, password, timezone } = req.body;
    const hash = await bcrypt.hash(password, 10);
    const plan = await prisma.plans.findFirst({ where: { code: 'free' } });
    
    const result = await prisma.$transaction(async (tx) => {
      const tenant = await tx.tenants.create({ data: { name: company_name, plan_id: plan!.id, timezone: timezone || 'Europe/Moscow' } });
      const user = await tx.users.create({ data: { tenant_id: tenant.id, role: 'admin', full_name: admin_name, email, password_hash: hash } });
      return { tenant, user };
    });
    res.json(result);
  } catch (e: any) { res.status(500).json({ error: e.message }); }
});

// Админские роуты (PWA)
app.get('/api/v1/admin/stats', authenticateJWT, async (req: any, res) => {
  const tid = req.user.tenant_id;
  const [active, trucks, photos] = await Promise.all([
    prisma.shifts.count({ where: { tenant_id: tid, status: { not: 'finished' } } }),
    prisma.dict_trucks.count({ where: { tenant_id: tid, is_busy: true } }),
    prisma.shifts.count({ where: { tenant_id: tid, updated_at: { gte: new Date(Date.now() - 86400000) } } })
  ]);
  res.json({ activeShifts: active, busyTrucks: trucks, photos24h: photos });
});

app.listen(PORT, () => console.log(`🚀 LogiShift Backend на порту ${PORT}`));
