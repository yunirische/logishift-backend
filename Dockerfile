# Используем легкий образ Node.js
FROM node:18-alpine

# ВАЖНО: Устанавливаем OpenSSL (критично для Prisma на Alpine)
RUN apk add --no-cache openssl

WORKDIR /app

# 1. Сначала копируем конфиги пакетов
COPY package*.json ./

# 2. Устанавливаем зависимости
RUN npm install

# 3. Копируем исходный код И ПАПКУ PRISMA
COPY . .

# 4. Генерируем Prisma Client
# Используем фиктивный URL, так как для генерации (не миграции) 
# реальное подключение к БД не нужно.
ENV DATABASE_URL="postgresql://johndoe:randompassword@localhost:5432/mydb"
RUN npx prisma generate

# 5. Собираем TypeScript проект
RUN npm run build

# 6. Открываем порт и запускаем
EXPOSE 3000
CMD ["node", "dist/index.js"]
