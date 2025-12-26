FROM node:20-alpine

# Устанавливаем зависимости для Prisma
RUN apk add --no-cache openssl libc6-compat

WORKDIR /app

# Копируем конфиги
COPY package*.json ./
COPY tsconfig.json ./

# Устанавливаем пакеты
RUN npm install

# Копируем схему и генерируем клиент
COPY prisma ./prisma/
RUN DATABASE_URL="postgresql://unused:unused@localhost:5432/unused" npx prisma generate

# Копируем код и собираем
COPY src ./src/
RUN npm run build

EXPOSE 3000

CMD ["node", "dist/index.js"]
