# Используем Node 20 для лучшей совместимости с Prisma
FROM node:20-alpine

# Устанавливаем системные библиотеки, без которых Prisma упадет на Alpine
RUN apk add --no-cache openssl libc6-compat

WORKDIR /app

# Копируем файлы зависимостей
COPY package*.json ./
COPY tsconfig.json ./

# Устанавливаем зависимости
RUN npm install

# Копируем папку Prisma (она должна быть в корне на GitHub!)
COPY prisma ./prisma/

# Генерируем клиент Prisma
# DATABASE_URL нужен только как заглушка для билда
RUN DATABASE_URL="postgresql://unused:unused@localhost:5432/unused" npx prisma generate

# Копируем весь исходный код
COPY src ./src/

# Компилируем TypeScript в JavaScript
RUN npm run build

# Открываем порт
EXPOSE 3000

# Запускаем именно через Node.js
CMD ["node", "dist/index.js"]
