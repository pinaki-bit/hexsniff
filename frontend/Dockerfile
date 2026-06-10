FROM node:20-alpine

WORKDIR /app

# Install dependencies
COPY package.json package-lock.json* ./
RUN npm install

# Copy source code
COPY . .

# Expose Vite dev port
EXPOSE 5173

# Start Vite via npm run dev with host binding
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]
