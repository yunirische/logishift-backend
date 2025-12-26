# Используем Node.js 20
FROM node:20-alpine

# Устанавливаем библиотеки для Prisma (обязательно для Alpine)
RUN apk add --no-cache openssl libc6-compat

WORKDIR /app

# Копируем файлы зависимостей (они должны быть в корне на GitHub!)
COPY package*.json ./
COPY tsconfig.json ./

# Устанавливаем зависимости
RUN npm install

# Копируем папку prisma (она должна быть в корне на GitHub!)
COPY prisma ./prisma/

# Генерируем клиент Prisma
RUN DATABASE_URL="postgresql://unused:unused@localhost:5432/unused" npx prisma generate

# Копируем исходный код
COPY src ./src/

# Собираем TypeScript в JavaScript
RUN npm run build

# Порт приложения
EXPOSE 3000

# Запуск приложения через Node.js
CMD ["node", "dist/index.js"]
