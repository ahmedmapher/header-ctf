FROM node:20-alpine

# Create app directory
WORKDIR /usr/src/app

# Install dependencies
COPY package*.json ./
RUN npm install --only=production

# Copy the rest of the app
COPY . .

# App listens on 3000
EXPOSE 3000

# Start the server
CMD ["npm", "start"]
