# Lab image: builds and serves one Next.js app. Local lab use only.
FROM node:22-alpine
WORKDIR /app
COPY package.json ./
RUN npm install --no-audit --no-fund
COPY . .
RUN npx next build
EXPOSE 3000
ENV PORT=3000
CMD ["npx", "next", "start", "-p", "3000"]
