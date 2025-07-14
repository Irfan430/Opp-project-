/**
 * Main Express Application
 * AI-Powered Cybersecurity Risk Simulation Platform - Backend
 */

require('dotenv').config();
const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const compression = require('compression');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss');
const hpp = require('hpp');
const rateLimit = require('express-rate-limit');

// Import database connections
const connectDB = require('./config/database');
const connectRedis = require('./config/redis');

// Import middleware
const errorHandler = require('./middleware/errorHandler');
const logger = require('./config/logger');

// Import routes
const authRoutes = require('./routes/auth');
const targetRoutes = require('./routes/targets');
const scanRoutes = require('./routes/scans');
const reportRoutes = require('./routes/reports');
const alertRoutes = require('./routes/alerts');
const billingRoutes = require('./routes/billing');
const userRoutes = require('./routes/users');
const phishingRoutes = require('./routes/phishing');
const cicdRoutes = require('./routes/cicd');

// Import socket handlers
const socketHandler = require('./sockets/socketHandler');

// Import services
const scanQueue = require('./services/scanQueue');
const scheduler = require('./services/scheduler');

class App {
  constructor() {
    this.app = express();
    this.server = http.createServer(this.app);
    this.io = socketIo(this.server, {
      cors: {
        origin: process.env.FRONTEND_URL || "http://localhost:3000",
        methods: ["GET", "POST"]
      }
    });
    
    this.port = process.env.PORT || 5000;
    this.isDevelopment = process.env.NODE_ENV === 'development';
    
    this.initializeMiddleware();
    this.initializeRoutes();
    this.initializeErrorHandling();
    this.initializeSocketIO();
  }

  /**
   * Initialize all middleware
   */
  initializeMiddleware() {
    // Security middleware
    this.app.use(helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          scriptSrc: ["'self'"],
          imgSrc: ["'self'", "data:", "https:"],
        },
      },
      crossOriginEmbedderPolicy: false
    }));

    // Rate limiting
    const limiter = rateLimit({
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: process.env.RATE_LIMIT_MAX_REQUESTS || 100,
      message: {
        error: 'Too many requests from this IP, please try again later.'
      },
      standardHeaders: true,
      legacyHeaders: false,
    });
    this.app.use('/api', limiter);

    // CORS configuration
    this.app.use(cors({
      origin: process.env.CORS_ORIGIN || 'http://localhost:3000',
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization', 'x-api-key']
    }));

    // Body parsing and compression
    this.app.use(compression());
    this.app.use(express.json({ limit: '10mb' }));
    this.app.use(express.urlencoded({ extended: true, limit: '10mb' }));

    // Data sanitization
    this.app.use(mongoSanitize());
    this.app.use(hpp());

    // XSS protection middleware
    this.app.use((req, res, next) => {
      if (req.body) {
        req.body = this.sanitizeObject(req.body);
      }
      next();
    });

    // Logging
    if (this.isDevelopment) {
      this.app.use(morgan('dev'));
    } else {
      this.app.use(morgan('combined', {
        stream: {
          write: (message) => logger.info(message.trim())
        }
      }));
    }

    // Health check endpoint
    this.app.get('/health', (req, res) => {
      res.status(200).json({
        status: 'OK',
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV,
        version: process.env.npm_package_version || '1.0.0'
      });
    });
  }

  /**
   * Initialize all routes
   */
  initializeRoutes() {
    // API routes
    this.app.use('/api/auth', authRoutes);
    this.app.use('/api/targets', targetRoutes);
    this.app.use('/api/scans', scanRoutes);
    this.app.use('/api/reports', reportRoutes);
    this.app.use('/api/alerts', alertRoutes);
    this.app.use('/api/billing', billingRoutes);
    this.app.use('/api/users', userRoutes);
    this.app.use('/api/phishing', phishingRoutes);
    this.app.use('/api/cicd', cicdRoutes);

    // API documentation (development only)
    if (this.isDevelopment && process.env.API_DOCS_ENABLED === 'true') {
      this.app.get('/api/docs', (req, res) => {
        res.json({
          message: 'API Documentation',
          endpoints: {
            auth: '/api/auth/*',
            targets: '/api/targets/*',
            scans: '/api/scans/*',
            reports: '/api/reports/*',
            alerts: '/api/alerts/*',
            billing: '/api/billing/*',
            users: '/api/users/*',
            phishing: '/api/phishing/*',
            cicd: '/api/cicd/*'
          }
        });
      });
    }

    // 404 handler for undefined routes
    this.app.use('*', (req, res) => {
      res.status(404).json({
        success: false,
        message: `Route ${req.originalUrl} not found`
      });
    });
  }

  /**
   * Initialize error handling
   */
  initializeErrorHandling() {
    this.app.use(errorHandler);
  }

  /**
   * Initialize Socket.IO
   */
  initializeSocketIO() {
    socketHandler(this.io);
  }

  /**
   * Sanitize object to prevent XSS
   */
  sanitizeObject(obj) {
    if (typeof obj === 'string') {
      return xss(obj);
    }
    if (typeof obj === 'object' && obj !== null) {
      const sanitized = {};
      for (const key in obj) {
        if (obj.hasOwnProperty(key)) {
          sanitized[key] = this.sanitizeObject(obj[key]);
        }
      }
      return sanitized;
    }
    return obj;
  }

  /**
   * Start the application
   */
  async start() {
    try {
      // Connect to databases
      await connectDB();
      await connectRedis();

      // Initialize background services
      await scanQueue.initialize();
      scheduler.start();

      // Start server
      this.server.listen(this.port, () => {
        logger.info(`🚀 Server running on port ${this.port}`);
        logger.info(`🔒 Environment: ${process.env.NODE_ENV}`);
        logger.info(`📊 Health check: http://localhost:${this.port}/health`);
        
        if (this.isDevelopment) {
          logger.info(`📚 API docs: http://localhost:${this.port}/api/docs`);
        }
      });

      // Graceful shutdown handling
      process.on('SIGTERM', this.gracefulShutdown.bind(this));
      process.on('SIGINT', this.gracefulShutdown.bind(this));

    } catch (error) {
      logger.error('Failed to start application:', error);
      process.exit(1);
    }
  }

  /**
   * Graceful shutdown
   */
  async gracefulShutdown(signal) {
    logger.info(`Received ${signal}. Starting graceful shutdown...`);

    try {
      // Stop accepting new connections
      this.server.close(() => {
        logger.info('HTTP server closed');
      });

      // Close Socket.IO connections
      this.io.close(() => {
        logger.info('Socket.IO server closed');
      });

      // Stop background services
      scheduler.stop();
      await scanQueue.close();

      logger.info('Graceful shutdown completed');
      process.exit(0);
    } catch (error) {
      logger.error('Error during graceful shutdown:', error);
      process.exit(1);
    }
  }
}

// Create and start the application
const app = new App();

if (require.main === module) {
  app.start();
}

module.exports = app;