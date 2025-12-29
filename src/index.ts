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

// --- ГЛОБАЛЬНЫЕ ПАТЧИ ---
(BigInt.prototype as any).toJSON = function () {
  return this.toString();
};

// --- ИНИЦИАЛИЗАЦИЯ ---
const prisma = new PrismaClient();
const app = express();
const PORT = process.env.PORT || 3000;
const UPLOAD_DIR = process.env.UPLOAD_DIR || './uploads';
const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-key';
const TG_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;

app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(UPLOAD_DIR));

// Расширяем тип Request для Express
declare global {
  namespace Express {
    interface Request {
      user?: { id: number; tenant_id: number; role: string };
    }
  }
}

interface AuthRequest extends Request {
  user?: { id: number; tenant_id: number; role: string };
}

// --- UTILS ---
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

// --- SERVICES ---

class MediaService {
  async downloadAndSave(fileId: string, tenantId: number): Promise<string> {
    if (!TG_BOT_TOKEN) throw new Error('TG_BOT_TOKEN missing in environment');
    
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
      if (!site || !shift) throw new Error('Ошибка контекста выбора объекта');
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

// --- GATEWAY CONTROLLER ---

const GatewayController = {
  async handleWebhook(req: Request, res: Response) {
    const { user_id, type, payload } = req.body;
    if (!user_id) return res.status(400).json({ error: "Missing user_id" });

    try {
      let user = await prisma.users.findUnique({ 
        where: { tg_user_id: BigInt(user_id) }, 
        include: { tenant: true } 
      });

      if (!user) {
        user = { tg_user_id: BigInt(user_id), tenant_id: null, role: 'driver', current_state: 'idle' } as any;
      }

      const activeShift = user?.id ? await prisma.shifts.findFirst({ 
        where: { user_id: user.id, status: { not: 'finished' } },
        include: { truck: true, site: true }
      }) : null;

      let result: any;

      if (type === 'callback') {
        result = await GatewayController.processCallback(user, payload.data, activeShift);
      } else if (type === 'text') {
        result = await GatewayController.processText(user, payload.text, activeShift);
      } else if (type === 'photo') {
        result = await shiftService.handleShiftPhoto(user.id, payload.file_id);
      }

      // ТЕПЕРЬ ТУТ ЧИСТО: Мы просто передаем готовое сообщение из результата
      return res.json(GatewayController.formatResponse(
        result?.message || "⚠️ Ошибка формирования интерфейса",
        result?.buttons || [],
        user.current_state,
        activeShift?.id,
        user.id || 0,
        user.last_menu_message_id?.toString()
      ));

    } catch (e: any) {
      console.error('GATEWAY ERROR:', e);
      return res.json({
        ui: { method: "sendMessage", text: `❌ Ошибка сервера: ${e.message}`, buttons: [], delete_original: false },
        state: { current_step: "error", active_shift_id: null }
      });
    }
  },

  // --- РЕНДЕР: МЕНЮ ВОДИТЕЛЯ (Интерфейс "Конфетка") ---
  renderDriverStatus(user: any, activeShift: any) {
    const timeNow = formatInTimezone(new Date(), user.tenant?.timezone);
    let text = `🚙 **МЕНЮ ВОДИТЕЛЯ**\n`;
    text += `🕒 ${timeNow}\n`;
    text += `────────────────────\n\n`;

    if (!activeShift) {
      text += `Статус: 💤 **ОТДЫХ**\n\n`;
      text += `У вас нет активной смены. Чтобы начать работу, нажмите кнопку ниже:`;
      return { 
        message: text, 
        buttons: [[{ text: "✅ Начать смену", callback_data: "START_SHIFT" }]] 
      };
    }

    // Индикаторы выполнения фотоотчетов
    const checkStart = activeShift.photo_start_url ? "✅" : "❌";
    const checkEnd = activeShift.photo_end_url ? "✅" : "❌";
    const checkInv = activeShift.photo_invoice_url ? "✅" : "❌";
    const startTime = formatInTimezone(activeShift.start_time, user.tenant?.timezone);

    text += `👷 **СМЕНА В ПРОЦЕССЕ**\n`;
    text += `⏱ **Старт:** ${startTime}\n`;
    text += `🚛 **Машина:** ${activeShift.truck?.name || '---'}\n`;
    text += `📍 **Объект:** ${activeShift.site?.name || '---'}\n`;
    text += `────────────────────\n`;
    text += `📸 **ОТЧЕТНОСТЬ:**\n`;
    text += `Одометр [Старт]: ${checkStart}\n`;
    text += `Одометр [Финиш]: ${checkEnd}\n`;
    text += `Накладная: ${checkInv}\n`;

    if (activeShift.comment) {
      text += `────────────────────\n`;
      text += `💬 **Ваш комментарий:**\n_${activeShift.comment}_\n`;
    }

    const buttons = [];
    if (activeShift.status === 'active') {
      buttons.push([{ text: "🏁 Завершить смену", callback_data: "END_SHIFT" }]);
      buttons.push([{ text: "🔄 Обновить статус", callback_data: "DRIVER_MENU" }]);
    } else {
      text += `\n⚠️ **ДЕЙСТВИЕ:** Пришлите фото для: *${user.current_state}*`;
      buttons.push([{ text: "❌ Отменить черновик", callback_data: "CANCEL" }]);
    }
    
    // Секретная кнопка для админа
    if (user.role === 'admin' || user.role === 'foreman') {
      buttons.push([{ text: "⚙️ Панель управления", callback_data: "ADMIN_MAIN" }]);
    }

    return { message: text, buttons };
  },

  // --- РЕНДЕР: ПАНЕЛЬ АДМИНА (Dashboard) ---
  async renderAdminPanel(user: any) {
    const tid = user.tenant_id;
    // Считаем живую статистику для дашборда
    const [active, busy, totalUsers] = await Promise.all([
      prisma.shifts.count({ where: { tenant_id: tid, status: { not: 'finished' } } }),
      prisma.dict_trucks.count({ where: { tenant_id: tid, is_busy: true } }),
      prisma.users.count({ where: { tenant_id: tid } })
    ]);

    let text = `👨‍💼 **ПАНЕЛЬ УПРАВЛЕНИЯ**\n`;
    text += `────────────────────\n\n`;
    text += `🟢 **Активных смен:** ${active}\n`;
    text += `🚛 **Машин в рейсе:** ${busy}\n`;
    text += `👷 **Водителей в базе:** ${totalUsers}\n\n`;
    text += `Выберите раздел:`;
    
    const buttons = [
      [
        { text: `🟢 Смены (${active})`, callback_data: "VIEW_ACTIVE" },
        { text: `👷 Онлайн (${active})`, callback_data: "VIEW_ONLINE" }
      ],
      [{ text: "➕ Создать смену за водителя", callback_data: "MANUAL_SHIFT" }],
      [{ text: "⚙️ Управление системой", callback_data: "ADMIN_SETTINGS" }],
      [{ text: "🚙 Меню Водителя", callback_data: "DRIVER_MENU" }]
    ];

    return { message: text, buttons };
  },

  // --- РЕНДЕР: ПОДМЕНЮ УПРАВЛЕНИЯ ---
  async renderAdminSettings(user: any) {
    let text = `⚙️ **УПРАВЛЕНИЕ СИСТЕМОЙ**\n`;
    text += `────────────────────\n`;
    text += `Здесь вы можете редактировать справочники и приглашать новых сотрудников.`;

    const buttons = [
      [{ text: "👥 Пригласить водителя", callback_data: "GEN_INVITE" }],
      [{ text: "🚛 Машины", callback_data: "EDIT_TRUCKS" }, { text: "📍 Объекты", callback_data: "EDIT_SITES" }],
      [{ text: "📦 Архив смен", callback_data: "REPORTS" }],
      [{ text: "⬅️ Назад в панель", callback_data: "ADMIN_MAIN" }]
    ];

    return { message: text, buttons };
  },

  async renderActiveShifts(user: any) {
    const shifts = await prisma.shifts.findMany({
      where: { tenant_id: user.tenant_id, status: { not: 'finished' } },
      include: { user: true, truck: true, site: true },
      orderBy: { start_time: 'desc' }
    });

    let text = `🟢 **АКТИВНЫЕ СМЕНЫ**\n`;
    text += `────────────────────\n\n`;

    if (shifts.length === 0) {
      text += `Сейчас нет открытых смен.`;
    } else {
      shifts.forEach((s, i) => {
        const time = formatInTimezone(s.start_time, user.tenant?.timezone);
        text += `${i + 1}. **${s.user.full_name}**\n`;
        text += `   🚛 ${s.truck?.name || '---'} | 📍 ${s.site?.name || '---'}\n`;
        text += `   ⏱ Старт: ${time}\n\n`;
      });
    }

    return { 
      message: text, 
      buttons: [[{ text: "⬅️ Назад", callback_data: "ADMIN_MAIN" }]] 
    };
  },

  async renderFleetList(user: any) {
    const trucks = await prisma.dict_trucks.findMany({
      where: { tenant_id: user.tenant_id },
      orderBy: { name: 'asc' }
    });

    let text = `🚛 **АВТОПАРК КОМПАНИИ**\n`;
    text += `────────────────────\n`;
    text += `🟢 — свободна, 🔴 — в рейсе\n\n`;

    const buttons = trucks.map(t => [
      { text: `${t.is_busy ? '🔴' : '🟢'} ${t.name} ${t.plate ? `[${t.plate}]` : ''}`, callback_data: `VIEW_TRK_${t.id}` }
    ]);

    buttons.push([{ text: "➕ Добавить машину", callback_data: "ADD_TRUCK" }]);
    buttons.push([{ text: "⬅️ Назад", callback_data: "ADMIN_SETTINGS" }]);

    return { message: text, buttons };
  },

  async renderSitesList(user: any) {
    const sites = await prisma.dict_sites.findMany({
      where: { tenant_id: user.tenant_id },
      orderBy: { name: 'asc' }
    });

    let text = `📍 **РАБОЧИЕ ОБЪЕКТЫ**\n`;
    text += `────────────────────\n\n`;

    const buttons = sites.map(s => [
      { text: `📍 ${s.name} ${s.odometer_required ? '📸' : ''}`, callback_data: `VIEW_STE_${s.id}` }
    ]);

    buttons.push([{ text: "➕ Добавить объект", callback_data: "ADD_SITE" }]);
    buttons.push([{ text: "⬅️ Назад", callback_data: "ADMIN_SETTINGS" }]);

    return { message: text, buttons };
  },

  async renderReportsArchive(user: any) {
    const lastShifts = await prisma.shifts.findMany({
      where: { tenant_id: user.tenant_id, status: 'finished' },
      include: { user: true, truck: true },
      take: 10,
      orderBy: { end_time: 'desc' }
    });

    let text = `📦 **ПОСЛЕДНИЕ 10 СМЕН**\n`;
    text += `────────────────────\n\n`;

    if (lastShifts.length === 0) {
      text += `Архив пока пуст.`;
    } else {
      lastShifts.forEach(s => {
        const date = s.end_time?.toLocaleDateString('ru-RU') || '---';
        text += `📅 ${date} | **${s.user.full_name}**\n`;
        text += `🚛 ${s.truck?.name} | ⏱ ${s.hours_worked} ч. | 💰 ${s.salary} ₽\n\n`;
      });
    }

    return { 
      message: text, 
      buttons: [[{ text: "⬅️ Назад", callback_data: "ADMIN_SETTINGS" }]] 
    };
  },

  async processText(user: any, text: string, activeShift: any) {
    const t = text.trim();
    if (t.startsWith('/start ')) return await GatewayController.handleRegistration(user, t.split(' ')[1]);
    if (!user.id) return { message: "⚠️ Доступ ограничен. Используйте ссылку-приглашение." };

    const tLower = t.toLowerCase();
    
    // Навигация по командам
    if (tLower === '/admin') {
      if (user.role !== 'admin' && user.role !== 'foreman') return { message: "🚫 Доступ запрещен." };
      return await GatewayController.renderAdminPanel(user);
    }
    if (tLower === '/driver' || tLower === '/start' || tLower === 'меню') {
      return GatewayController.renderDriverStatus(user, activeShift);
    }

    // Текст как комментарий
    if (user.current_state === 'active' && activeShift) {
      await prisma.shifts.update({ where: { id: activeShift.id }, data: { comment: t } });
      const updated = await prisma.shifts.findUnique({ where: { id: activeShift.id }, include: { truck: true, site: true } });
      const response = GatewayController.renderDriverStatus(user, updated);
      return { ...response, message: "✅ Комментарий сохранен!\n\n" + response.message };
    }

    return { message: "❓ Неизвестная команда. Используйте кнопки меню." };
  },

  async processCallback(user: any, data: string, activeShift: any) {
    // Навигация (Рендеры)
    if (data === 'ADMIN_MAIN') return await GatewayController.renderAdminPanel(user);
    if (data === 'ADMIN_SETTINGS') return await GatewayController.renderAdminSettings(user);
    if (data === 'DRIVER_MENU') return GatewayController.renderDriverStatus(user, activeShift);
    if (data === 'VIEW_ACTIVE') return await GatewayController.renderActiveShifts(user);
    if (data === 'EDIT_TRUCKS') return await GatewayController.renderFleetList(user);
    if (data === 'EDIT_SITES') return await GatewayController.renderSitesList(user);
    if (data === 'REPORTS') return await GatewayController.renderReportsArchive(user);
    
    // Логика водителя
    if (data === 'START_SHIFT') {
      if (activeShift) return { message: "⚠️ Смена уже идет." };
      await shiftService.startShiftDraft(user.id);
      const trucks = await prisma.dict_trucks.findMany({ where: { tenant_id: user.tenant_id, is_active: true, is_busy: false } });
      return { 
        message: "🚚 **ВЫБОР МАШИНЫ**\nВыберите свободный транспорт:", 
        buttons: [...trucks.map(t => [{ text: `🚛 ${t.name}`, callback_data: `TRK_${t.id}` }]), [{ text: "❌ Отмена", callback_data: "CANCEL" }]]
      };
    }
    
    if (data.startsWith('TRK_')) {
      await shiftService.selectTruck(user.id, parseId(data.split('_')[1]));
      const sites = await prisma.dict_sites.findMany({ where: { tenant_id: user.tenant_id, is_active: true } });
      return { 
        message: "📍 **ВЫБОР ОБЪЕКТА**\nВыберите объект работы:", 
        buttons: [...sites.map(s => [{ text: `📍 ${s.name}`, callback_data: `STE_${s.id}` }]), [{ text: "❌ Отмена", callback_data: "CANCEL" }]]
      };
    }

    if (data.startsWith('STE_')) {
      const res = await shiftService.selectSite(user.id, parseId(data.split('_')[1]));
      const updated = await prisma.shifts.findFirst({ where: { user_id: user.id, status: { not: 'finished' } }, include: { truck: true, site: true } });
      return GatewayController.renderDriverStatus(user, updated);
    }

    if (data === 'END_SHIFT') return await shiftService.requestEndShift(user.id);
    if (data === 'CANCEL') { await shiftService.cancelShift(user.id); return GatewayController.renderDriverStatus(user, null); }
    
    // Логика админа
    if (data === 'GEN_INVITE') return await GatewayController.generateInviteLink(user);

    if (data.startsWith('VIEW_TRK_')) {
      return { message: "ℹ️ Детальная информация о машине будет доступна в WebApp.", buttons: [[{ text: "⬅️ Назад", callback_data: "EDIT_TRUCKS" }]] };
    }
    if (data.startsWith('VIEW_STE_')) {
      return { message: "ℹ️ Настройки объекта (одометр, накладные) будут доступны в WebApp.", buttons: [[{ text: "⬅️ Назад", callback_data: "EDIT_SITES" }]] };
    }

    // Заглушки для действий
    if (data === 'ADD_TRUCK' || data === 'ADD_SITE') {
      return { message: "🏗 Для добавления новых сущностей используйте WebApp (раздел Справочники).", buttons: [[{ text: "⬅️ Назад", callback_data: "ADMIN_SETTINGS" }]] };
    }
    
    // Заглушки для будущего функционала
    const adminStubs = ['VIEW_ACTIVE', 'VIEW_ONLINE', 'VIEW_PHOTOS', 'MANUAL_SHIFT', 'EDIT_TRUCKS', 'EDIT_SITES', 'REPORTS', 'SET_TZ', 'BILLING'];
    if (adminStubs.includes(data)) {
      return { message: "⏳ Этот раздел сейчас в разработке и скоро появится в WebApp.", buttons: [[{ text: "⬅️ Назад", callback_data: "ADMIN_SETTINGS" }]] };
    }

    return { message: "Меню:" };
  },

  async generateInviteLink(adminUser: any) {
    const inviteCode = Math.random().toString(36).substring(2, 10).toUpperCase();
    await prisma.invites.create({ data: { tenant_id: adminUser.tenant_id, code: inviteCode, expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), status: 'pending' } });
    const link = `https://t.me/sift_test_bot?start=${inviteCode}`;
    return { message: `✉️ **ИНВАЙТ-ССЫЛКА ДЛЯ ВОДИТЕЛЯ**\n\n\`${link}\`\n\nАктивна 7 дней.`, buttons: [[{ text: "⬅️ Назад", callback_data: "ADMIN_SETTINGS" }]] };
  },

  async handleRegistration(user: any, inviteCode: string) {
    try {
      const invite = await prisma.invites.findFirst({ where: { code: inviteCode, status: 'pending', expires_at: { gte: new Date() } } });
      if (!invite) return { message: "❌ Код недействителен или просрочен." };
      const existingUser = await prisma.users.findUnique({ where: { tg_user_id: user.tg_user_id } });
      await prisma.$transaction(async (tx) => {
        if (existingUser) {
          await tx.users.update({ where: { id: existingUser.id }, data: { tenant_id: invite.tenant_id, role: 'driver', current_state: 'idle' } });
        } else {
          await tx.users.create({ data: { tenant_id: invite.tenant_id, role: 'driver', tg_user_id: user.tg_user_id, current_state: 'idle', full_name: 'Новый водитель' } });
        }
        await tx.invites.update({ where: { id: invite.id }, data: { status: 'used' } });
      });
      return { message: "✅ Регистрация успешна!", buttons: [[{ text: "🚀 В личный кабинет", callback_data: "DRIVER_MENU" }]] };
    } catch (e) { return { message: "❌ Ошибка при регистрации." }; }
  },

  formatResponse(text: string, buttons: any[] = [], state: string = 'idle', shiftId?: number, userInternalId?: number, lastMenuId?: string) {
    return {
      ui: { method: "sendMessage", text, buttons, delete_original: !!lastMenuId },
      state: { current_step: state, active_shift_id: shiftId || null, user_internal_id: userInternalId, last_menu_message_id: lastMenuId || null }
    };
  }
};

// --- ROUTES ---
const api = express.Router();

api.post('/gateway', GatewayController.handleWebhook);

api.post('/users/set-menu-id', async (req, res) => {
  try {
    const { user_id, message_id } = req.body;
    const uid = parseInt(user_id);
    
    // Если пользователь еще не зарегистрирован (ID 0 или NaN), просто отвечаем "ОК" без ошибки
    if (!uid || isNaN(uid)) {
      return res.json({ success: true, note: 'User not registered yet, skipping' });
    }

    await prisma.users.update({ 
      where: { id: uid }, 
      data: { last_menu_message_id: BigInt(message_id) } 
    });
    res.json({ success: true });
  } catch (e: any) { 
    console.error('SET MENU ID ERROR:', e);
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

app.listen(PORT, () => console.log(`🚀 Server on port ${PORT}`));
