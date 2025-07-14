# Use Node.js 18 Alpine for smaller image size
FROM node:18-alpine

# Install security scanning tools
RUN apk update && apk add --no-cache \
    nmap \
    nmap-scripts \
    nikto \
    curl \
    python3 \
    py3-pip \
    && rm -rf /var/cache/apk/*

# Create app directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production && npm cache clean --force

# Create non-root user for security
RUN addgroup -g 1001 -S nodejs
RUN adduser -S backend -u 1001

# Create necessary directories
RUN mkdir -p /app/logs /app/uploads /app/scan_results /app/reports && \
    chown -R backend:nodejs /app

# Copy application code
COPY --chown=backend:nodejs . .

# Switch to non-root user
USER backend

# Expose port
EXPOSE 3001

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3001/api/health || exit 1

# Start the application
CMD ["npm", "start"]