# Stage 1: build the React-free Vite frontend
FROM node:20-bookworm-slim AS fe
WORKDIR /fe
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ .
RUN npm run build

# Stage 2: API + static frontend in one container
FROM node:20-bookworm-slim
WORKDIR /app
COPY backend/package*.json ./
RUN npm ci --omit=dev
COPY backend/ .
COPY --from=fe /fe/dist ./public
ENV NODE_ENV=production PORT=8080 DB_PATH=/data/vulncentral.db
VOLUME /data
EXPOSE 8080
CMD ["node", "src/server.js"]
