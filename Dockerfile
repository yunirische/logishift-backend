FROM node:20-alpine

# Устанавливаем системные зависимости для Prisma
RUN apk add --no-cache openssl libc6-compat

WORKDIR /app

# Копируем файлы зависимостей
COPY package*.json ./
# Если есть tsconfig, копируем и его
COPY tsconfig.json ./ 

# Устанавливаем зависимости (включая Prisma CLI)
RUN npm install

# Копируем схему ПЕРЕД генерацией
COPY prisma ./prisma/

# Генерируем клиент. 
# Мы используем локальный бинарник из node_modules, это надежнее чем npx.
# Добавляем флаг --schema, чтобы точно указать путь.
RUN DATABASE_URL="postgresql://unused:unused@localhost:5432/unused" ./node_modules/.bin/prisma generate --schema=./prisma/schema.prisma

# Копируем остальной код
COPY src ./src/

# Собираем TS
RUN npm run build

EXPOSE 3000

CMD ["node", "dist/index.js"]
