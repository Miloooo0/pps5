FROM node:20-alpine

# Crear usuario no root (buena práctica de seguridad)
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

WORKDIR /app

# Copiamos solo dependencias primero (mejor caché)
COPY package*.json ./

RUN npm install

# Copiamos el resto del código
COPY . .

# Cambiamos propietario
RUN chown -R appuser:appgroup /app

USER appuser

EXPOSE 3001

CMD ["npm", "start"]
