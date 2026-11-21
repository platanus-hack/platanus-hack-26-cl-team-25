FROM node:22-alpine
WORKDIR /app
ENV NODE_ENV=production
COPY package.json package-lock.json ./
COPY node_modules ./node_modules
COPY server.js ./
COPY src ./src
COPY db ./db
COPY files ./files
COPY test ./test
USER node
EXPOSE 3000
CMD ["node", "server.js"]
