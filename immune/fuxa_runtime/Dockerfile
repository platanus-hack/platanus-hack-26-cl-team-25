FROM node:22-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends unixodbc-dev python3 make g++ \
    && rm -rf /var/lib/apt/lists/*
ENV npm_config_nodedir=/usr/local
WORKDIR /app/server
COPY source/server/package*.json ./
RUN npm ci --no-audit --no-fund
COPY source/server /app/server
COPY source/client/dist /app/client/dist
COPY observe.cjs start.cjs gateway.cjs check.cjs read-events.cjs plant.cjs plant.svg /immune/
USER node
