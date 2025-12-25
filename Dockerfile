FROM node:20-alpine

# Устанавливаем системные библиотеки для Prisma
RUN apk add --no-cache openssl libc6-compat

WORKDIR /app

# Копируем файлы зависимостей
COPY package*.json ./
COPY tsconfig.json ./

# Устанавливаем зависимости
RUN npm install

# Копируем схему Prisma
COPY prisma ./prisma/

# Генерируем клиент Prisma (используем dummy URL для этапа билда)
RUN DATABASE_URL="postgresql://unused:unused@localhost:5432/unused" npx prisma generate

# Копируем исходный код
COPY src ./src/

# Собираем TypeScript
RUN npm run build

EXPOSE 3000

# Запуск
CMD ["node", "dist/index.js"]
