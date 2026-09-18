# Memory Forensics Platform -- Frontend (React/Vite, served via nginx)
#
# NOTE: this Dockerfile has not been build-tested in an actual Docker
# environment (none was available while authoring it) -- please verify with
# `docker compose up --build` and report any issues before relying on it.
#
# VITE_API_BASE_URL must be provided as a build ARG, not a runtime
# environment variable: Vite bakes environment variables into the compiled
# JS at build time (import.meta.env), and the output of this build is a
# static site with no server-side process to read env vars from at runtime.
# If you need to point at a different backend URL, rebuild with
# `docker compose build --build-arg VITE_API_BASE_URL=https://your-api/api`
# (or override via docker-compose.yml's build.args).

# --- Stage 1: build the static assets ---
FROM node:20-slim AS build
WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .

ARG VITE_API_BASE_URL=http://localhost:8000/api
ENV VITE_API_BASE_URL=$VITE_API_BASE_URL

RUN npm run build

# --- Stage 2: serve the built assets ---
FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Run entirely as the image's built-in unprivileged "nginx" user, not root.
# This requires listening on a port >1024 (see nginx.conf: 8080, not 80),
# since binding privileged ports needs root -- the whole reason nginx's
# master process runs as root by default otherwise.
RUN chown -R nginx:nginx /usr/share/nginx/html /var/cache/nginx /var/log/nginx /etc/nginx/conf.d \
    && touch /var/run/nginx.pid \
    && chown nginx:nginx /var/run/nginx.pid
USER nginx

EXPOSE 8080

CMD ["nginx", "-g", "daemon off;"]
