# Use Node 18 as established by environment constraints
FROM node:18-slim

WORKDIR /app

# Install dependencies first for caching
COPY package.json package-lock.json ./
RUN npm install

# Copy source code
COPY . .

# Expose Vite Port
EXPOSE 5173

# Default to dev server for hot-reload (volume mount required in compose)
CMD ["npm", "run", "dev", "--", "--host"]
