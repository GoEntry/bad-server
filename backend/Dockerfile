FROM node:22-alpine
RUN mkdir /app
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN mkdir -p src/public/temp
CMD ["npm", "run", "dev"]
