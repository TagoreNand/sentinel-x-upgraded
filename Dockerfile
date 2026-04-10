FROM node:22-alpine AS base
WORKDIR /app

COPY package.json pnpm-lock.yaml ./
RUN corepack enable || true

COPY . .

RUN npm install
RUN npm run build

EXPOSE 3000
CMD ["npm", "run", "start"]
