FROM node:22-alpine
ENV NODE_ENV=production
# Dependencies come from package-lock.json and are installed one level above /app, where Node's upward module
# lookup finds them (/app/src -> /app -> /). They stay in place when a release directory is mounted over /app,
# as the Inmune judge and test containers do (without network), so node_modules is never part of a release.
WORKDIR /
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund && rm package.json package-lock.json
WORKDIR /app
COPY package.json package-lock.json ./
COPY server.js ./
COPY src ./src
COPY db ./db
COPY files ./files
COPY test ./test
USER node
EXPOSE 3000
CMD ["node", "server.js"]
