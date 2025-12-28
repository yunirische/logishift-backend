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

      // Если пользователь не найден - создаем временный объект-заглушку
      if (!user) {
        user = { 
          tg_user_id: BigInt(user_id), 
          tenant_id: null, 
          role: 'driver',
          current_state: 'idle'
        } as any;
      }

      // Активную смену ищем только если пользователь существует в БД
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

      const timeStr = formatInTimezone(new Date(), user.tenant?.timezone);
      
      return res.json(GatewayController.formatResponse(
        `${result?.message || "Меню:"}\n\n🕒 ${timeStr}`,
        result?.buttons || [],
        user.current_state,
        activeShift?.id,
        user.id,
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

renderDriverStatus(user: any, activeShift: any) {
    let text = `🚗 **МЕНЮ ВОДИТЕЛЯ**\n`;
    text += `────────────────────\n`;

    if (!activeShift) {
      text += `Состояние: 💤 **Отдых**\n`;
      text += `У вас нет активной смены. Чтобы начать работу, нажмите кнопку ниже.`;
      return { text, buttons: [[{ text: "✅ Начать смену", callback_data: "START_SHIFT" }]] };
    }

    // Формируем индикаторы фото
    const checkStart = activeShift.photo_start_url ? "✅" : (user.current_state === 'awaiting_odo_start' ? "⏳" : "❌");
    const checkEnd = activeShift.photo_end_url ? "✅" : (user.current_state === 'awaiting_odo_end' ? "⏳" : "❌");
    const checkInv = activeShift.photo_invoice_url ? "✅" : (user.current_state === 'awaiting_invoice' ? "⏳" : "❌");

    const timeStr = formatInTimezone(activeShift.start_time, user.tenant?.timezone);

    text += `👷 **В РАБОТЕ**\n`;
    text += `⏱ **Старт:** ${timeStr}\n`;
    text += `🚛 **Машина:** ${activeShift.truck?.name || '---'}\n`;
    text += `📍 **Объект:** ${activeShift.site?.name || '---'}\n`;
    text += `────────────────────\n`;
    text += `📸 **ФОТООТЧЕТ:**\n`;
    text += `Одометр [S]: ${checkStart} | [F]: ${checkEnd} | Чек: ${checkInv}\n`;

    if (activeShift.comment) {
      text += `────────────────────\n`;
      text += `💬 **Комментарий:** ${activeShift.comment}\n`;
    }

    const buttons = [];
    if (activeShift.status === 'active') {
      buttons.push([{ text: "🏁 Завершить смену", callback_data: "END_SHIFT" }]);
      buttons.push([{ text: "📝 Добавить комментарий", callback_data: "ADD_COMMENT" }]);
    } else {
      text += `\n⚠️ **Ожидание действия:** Пришлите фото!`;
      buttons.push([{ text: "❌ Отменить черновик", callback_data: "CANCEL" }]);
    }
    
    // Если это админ, добавим кнопку возврата в админку
    if (user.role === 'admin' || user.role === 'foreman') {
      buttons.push([{ text: "⚙️ Вернуться в Админ-панель", callback_data: "ADMIN_MAIN" }]);
    }

    return { text, buttons };
  },

  async renderAdminPanel(user: any) {
    const tid = user.tenant_id;
    
    // Собираем быструю статистику
    const [activeShifts, busyTrucks, usersCount] = await Promise.all([
      prisma.shifts.count({ where: { tenant_id: tid, status: { not: 'finished' } } }),
      prisma.dict_trucks.count({ where: { tenant_id: tid, is_busy: true } }),
      prisma.users.count({ where: { tenant_id: tid } })
    ]);

    let text = `👨‍💼 **ПАНЕЛЬ УПРАВЛЕНИЯ**\n`;
    text += `Компания: **${user.tenant?.name}**\n`;
    text += `────────────────────\n`;
    
    const buttons = [
      [
        { text: `🟢 Смены (${activeShifts})`, callback_data: "VIEW_ACTIVE" },
        { text: `👷 Онлайн (${activeShifts})`, callback_data: "VIEW_ONLINE" }
      ],
      [{ text: `🖼 Фото за 24ч (---)`, callback_data: "VIEW_PHOTOS" }],
      [{ text: "➕ Создать смену за водителя", callback_data: "MANUAL_SHIFT" }],
      [{ text: "⚙️ Управление системой", callback_data: "ADMIN_SETTINGS" }],
      [{ text: "🚗 Перейти в режим водителя", callback_data: "DRIVER_MENU" }]
    ];

    return { text, buttons };
  },

  async renderAdminSettings(user: any) {
    const tid = user.tenant_id;
    const usersCount = await prisma.users.count({ where: { tenant_id: tid } });

    let text = `🛠 **УПРАВЛЕНИЕ СИСТЕМОЙ**\n`;
    text += `Настройте справочники и параметры компании.`;

    const buttons = [
      [
        { text: `👥 Пользователи (${usersCount})`, callback_data: "GEN_INVITE" }, // Пока ведем на инвайт
        { text: `📦 Архив смен`, callback_data: "REPORTS" }
      ],
      [
        { text: `🚛 Машины`, callback_data: "EDIT_TRUCKS" },
        { text: `📍 Объекты`, callback_data: "EDIT_SITES" }
      ],
      [
        { text: `📊 Отчеты`, callback_data: "REPORTS" },
        { text: `🌍 Часовой пояс`, callback_data: "SET_TZ" }
      ],
      [{ text: `💳 Тариф: Бесплатный`, callback_data: "BILLING" }],
      [{ text: "⬅️ Назад в панель", callback_data: "ADMIN_MAIN" }]
    ];

    return { text, buttons };
  },



  async processCallback(user: any, data: string, activeShift: any) {
    if (!user.id) return { message: "⚠️ Ошибка авторизации." };

    // --- Навигация ---
    if (data === 'ADMIN_MAIN') return await GatewayController.renderAdminPanel(user);
    if (data === 'ADMIN_SETTINGS') return await GatewayController.renderAdminSettings(user);
    if (data === 'DRIVER_MENU') return GatewayController.renderDriverStatus(user, activeShift);
    
    // --- Логика Водителя ---
    if (data === 'START_SHIFT') {
      if (activeShift) return { message: "⚠️ Смена уже идет." };
      await shiftService.startShiftDraft(user.id);
      const trucks = await prisma.dict_trucks.findMany({ where: { tenant_id: user.tenant_id, is_active: true, is_busy: false } });
      return { 
        message: "🚚 **ВЫБОР МАШИНЫ**\nВыберите транспорт из списка:", 
        buttons: [...trucks.map(t => [{ text: `🚛 ${t.name}`, callback_data: `TRK_${t.id}` }]), [{ text: "❌ Отмена", callback_data: "CANCEL" }]]
      };
    }
    
    if (data.startsWith('TRK_')) {
      await shiftService.selectTruck(user.id, parseId(data.split('_')[1]));
      const sites = await prisma.dict_sites.findMany({ where: { tenant_id: user.tenant_id, is_active: true } });
      return { 
        message: "📍 **ВЫБОР ОБЪЕКТА**\nГде сегодня работаем?", 
        buttons: [...sites.map(s => [{ text: `📍 ${s.name}`, callback_data: `STE_${s.id}` }]), [{ text: "❌ Отмена", callback_data: "CANCEL" }]]
      };
    }

    if (data.startsWith('STE_')) {
      const res = await shiftService.selectSite(user.id, parseId(data.split('_')[1]));
      return GatewayController.renderDriverStatus(user, await prisma.shifts.findFirst({ where: { user_id: user.id, status: { not: 'finished' } } }));
    }

    if (data === 'END_SHIFT') return await shiftService.requestEndShift(user.id);
    if (data === 'CANCEL') { await shiftService.cancelShift(user.id); return GatewayController.renderDriverStatus(user, null); }
    
    // --- Логика Админа ---
    if (data === 'GEN_INVITE') return await GatewayController.generateInviteLink(user);
    
    // Заглушки
    if (['REPORTS', 'VIEW_ACTIVE', 'VIEW_ONLINE', 'VIEW_PHOTOS', 'MANUAL_SHIFT', 'EDIT_TRUCKS', 'EDIT_SITES', 'SET_TZ', 'BILLING'].includes(data)) {
      return { message: "⏳ Этот раздел сейчас находится в разработке и будет доступен в WebApp.", buttons: [[{ text: "⬅️ Назад", callback_data: "ADMIN_SETTINGS" }]] };
    }

    return { message: "Команда получена: " + data };
  },

  async processText(user: any, text: string, activeShift: any) {
    if (!text) return { message: "Меню:" };
    const t = text.trim();
    
    // 1. Регистрация по ссылке (всегда высший приоритет)
    if (t.startsWith('/start ')) {
      const inviteCode = t.split(' ')[1];
      return await GatewayController.handleRegistration(user, inviteCode);
    }

    // 2. Проверка авторизации
    if (!user.id || !user.tenant_id) {
      return { message: "⚠️ Доступ ограничен. Нужна ссылка-приглашение." };
    }

    const tLower = t.toLowerCase();
    
    // 3. Команда АДМИН (Панель управления)
    if (tLower === '/admin') {
      if (user.role !== 'admin' && user.role !== 'foreman') {
        return { message: "🚫 У вас нет прав администратора." };
      }
      return await GatewayController.renderAdminPanel(user);
    }

    // 4. Команда ВОДИТЕЛЬ или СТАРТ (Личный кабинет водителя)
    if (tLower === '/driver' || tLower === '/start' || tLower === 'меню') {
      return GatewayController.renderDriverStatus(user, activeShift);
    }

    // 5. Если просто прислали текст при активной смене — это комментарий
    if (user.current_state === 'active' && activeShift) {
      await prisma.shifts.update({ where: { id: activeShift.id }, data: { comment: t } });
      // После сохранения комментария возвращаем водителя в его меню
      const updatedShift = await prisma.shifts.findUnique({ where: { id: activeShift.id }, include: { truck: true, site: true } });
      const response = GatewayController.renderDriverStatus(user, updatedShift);
      return { ...response, message: "✅ Комментарий сохранен!\n\n" + response.text };
    }

    return { message: "❓ Неизвестная команда. Используйте /driver или /admin." };
  },

  // Добавьте эту функцию внутрь объекта GatewayController
  async generateInviteLink(adminUser: any) {
    try {
      // Генерируем случайный код из 8 символов
      const inviteCode = Math.random().toString(36).substring(2, 10).toUpperCase();
      const expiresAt = new Date();
      expiresAt.setDate(expiresAt.getDate() + 7); // Ссылка живет 7 дней

      await prisma.invites.create({
        data: {
          tenant_id: adminUser.tenant_id,
          code: inviteCode,
          expires_at: expiresAt,
          status: 'pending'
        }
      });

      // ЗАМЕНИТЕ 'YourBotName' на реальный username вашего бота без @
      const botUsername = 'sift_test_bot'; 
      const link = `https://t.me/${botUsername}?start=${inviteCode}`;

      return {
        message: `✉️ **Ссылка-приглашение для водителя:**\n\n\`${link}\`\n\n_Нажмите на ссылку, чтобы скопировать её. Перешлите её водителю. Она будет активна 7 дней._`,
        buttons: [[{ text: "🔙 В меню", callback_data: "MENU" }]]
      };
    } catch (e: any) {
      console.error('GENERATE INVITE ERROR:', e);
      return { message: "❌ Не удалось создать приглашение." };
    }
  },

  async handleRegistration(user: any, inviteCode: string) {
    try {
      // 1. Ищем инвайт в БД
      const invite = await prisma.invites.findFirst({
        where: { 
          code: inviteCode,
          status: 'pending',
          expires_at: { gte: new Date() }
        }
      });

      if (!invite) {
        return { message: "❌ Код недействителен, использован или просрочен." };
      }

      // 2. Ищем, есть ли уже такой пользователь в базе (мог зайти без кода ранее)
      const existingUser = await prisma.users.findUnique({
        where: { tg_user_id: user.tg_user_id }
      });

      if (existingUser && existingUser.tenant_id) {
        return { message: "⚠️ Вы уже зарегистрированы в системе." };
      }

      // 3. Активируем регистрацию
      await prisma.$transaction(async (tx) => {
        if (existingUser) {
          // ОБНОВЛЯЕМ существующую "пустышку"
          await tx.users.update({
            where: { id: existingUser.id },
            data: { 
              tenant_id: invite.tenant_id,
              role: 'driver',
              current_state: 'idle',
              full_name: 'Новый водитель' 
            }
          });
        } else {
          // СОЗДАЕМ нового, если его нет
          await tx.users.create({
            data: { 
              tenant_id: invite.tenant_id,
              role: 'driver',
              tg_user_id: user.tg_user_id,
              current_state: 'idle',
              full_name: 'Новый водитель'
            }
          });
        }

        // Помечаем инвайт как использованный
        await tx.invites.update({
          where: { id: invite.id },
          data: { status: 'used' }
        });
      });

      return { 
        message: "✅ Регистрация завершена успешно!\n\nТеперь вам доступны функции управления сменами.",
        buttons: [[{ text: "🚀 Начать смену", callback_data: "START_SHIFT" }]]
      };
      
    } catch (e: any) {
      console.error('REGISTRATION ERROR:', e);
      return { message: "❌ Ошибка при регистрации. Попробуйте позже." };
    }
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
