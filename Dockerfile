FROM node:20-alpine

WORKDIR /app

# Сначала копируем файлы зависимостей
COPY package*.json ./
COPY tsconfig.json ./

# Устанавливаем зависимости
RUN npm install

# Копируем схему Prisma и генерируем клиент (КРИТИЧНО)
COPY prisma ./prisma/
RUN npx prisma generate

# Копируем исходный код
COPY src ./src/

# Собираем проект
RUN npm run build

EXPOSE 3000

# Запуск из папки dist (куда tsc положит результат)
CMD ["node", "dist/index.js"]
