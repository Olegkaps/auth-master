FROM node:22-alpine AS builder
WORKDIR /web
COPY package.json package-lock.json ./
RUN npm ci --no-audit
COPY . .
RUN npm run build

FROM nginx:1.27-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=builder /web/dist /usr/share/nginx/html
EXPOSE 8080
