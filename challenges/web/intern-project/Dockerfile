FROM node:20-alpine

WORKDIR /app
COPY package.json /app/

RUN npm install --omit=dev

COPY server.js /app/server.js
COPY public /app/public

EXPOSE 3000 3001

CMD ["node","server.js"]
