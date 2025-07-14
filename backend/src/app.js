const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const mongoSanitize = require('express-mongo-sanitize');
const rateLimit = require('express-rate-limit');
const slowDown = require('express-slow-down');
const hpp = require('hpp');
const morgan = require('morgan');
const { createServer } = require('http');
const { Server } = require('socket.io');
const Redis = require('redis');
require('dotenv').config();

// Import services and middleware
const logger = require('./utils/logger');
const errorHandler = require('./middleware/errorHandler');
const notFoundHandler = require('./middleware/notFound');
const authMiddleware = require('./middleware/auth');
const setupSocketHandlers = require('./services/socketService');

// Import routes
const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/users');
const targetRoutes = require('./routes/targets');
const scanRoutes = require('./routes/scans');
const reportRoutes = require('./routes/reports');
const phishingRoutes = require('./routes/phishing');
const billingRoutes = require('./routes/billing');
const analyticsRoutes = require('./routes/analytics');
const webhookRoutes = require('./routes/webhooks');
const apiRoutes = require('./routes/api');
const healthRoutes = require('./routes/health');

/**
 * Main Application Class
 * Handles Express app configuration, middleware setup, and server initialization
 */
class CybersecurityPlatformApp {
  constructor() {
    this.app = express();
    this.server = createServer(this.app);
    this.io = new Server(this.server, {
      cors: {
        origin: process.env.FRONTEND_URL || "http://localhost:3000",
        methods: ["GET", "POST"],
        credentials: true
      }
    });
    this.redis = null;
    
    this.initializeRedis();
    this.initializeMiddleware();
    this.initializeRoutes();
    this.initializeErrorHandling();
    this.initializeSocket();
  }

  /**
   * Initialize Redis connection for caching and job queues
   */
  async initializeRedis() {
    try {
      this.redis = Redis.createClient({
        host: process.env.REDIS_HOST || 'localhost',
        port: process.env.REDIS_PORT || 6379,
        password: process.env.REDIS_PASSWORD || undefined,
        retryDelayOnFailover: 100,
        enableReadyCheck: false,
        maxRetriesPerRequest: null
      });

      this.redis.on('error', (err) => {
        logger.error('Redis connection error:', err);
      });

      this.redis.on('connect', () => {
        logger.info('Connected to Redis');
      });

      await this.redis.connect();
      
      // Make Redis available globally
      global.redis = this.redis;
    } catch (error) {
      logger.error('Failed to initialize Redis:', error);
    }
  }

  /**
   * Initialize Express middleware stack
   */
  initializeMiddleware() {
    // Trust proxy for proper IP handling
    this.app.set('trust proxy', 1);

    // Security middleware
    this.app.use(helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
          scriptSrc: ["'self'"],
          fontSrc: ["'self'", "https://fonts.gstatic.com"],
          imgSrc: ["'self'", "data:", "https:"],
        },
      },
      crossOriginEmbedderPolicy: false
    }));

    // CORS configuration
    this.app.use(cors({
      origin: (origin, callback) => {
        const allowedOrigins = [
          process.env.FRONTEND_URL,
          'http://localhost:3000',
          'http://localhost:3001',
          'https://localhost:3000'
        ].filter(Boolean);

        if (!origin || allowedOrigins.includes(origin)) {
          callback(null, true);
        } else {
          callback(new Error('Not allowed by CORS'));
        }
      },
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
    }));

    // Rate limiting
    const limiter = rateLimit({
      windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
      max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100,
      message: {
        error: 'Too many requests from this IP, please try again later.',
        code: 'RATE_LIMIT_EXCEEDED'
      },
      standardHeaders: true,
      legacyHeaders: false,
      skip: (req) => {
        // Skip rate limiting for health checks
        return req.path === '/api/health';
      }
    });

    // Slow down middleware for additional protection
    const speedLimiter = slowDown({
      windowMs: 15 * 60 * 1000, // 15 minutes
      delayAfter: 50, // allow 50 requests per windowMs without delay
      delayMs: 500 // add 500ms delay per request after delayAfter
    });

    this.app.use('/api/', limiter);
    this.app.use('/api/', speedLimiter);

    // Body parsing middleware
    this.app.use(express.json({ 
      limit: '10mb',
      verify: (req, res, buf) => {
        // Store raw body for webhook verification
        if (req.path.startsWith('/api/webhooks/')) {
          req.rawBody = buf;
        }
      }
    }));
    this.app.use(express.urlencoded({ extended: true, limit: '10mb' }));

    // Data sanitization
    this.app.use(mongoSanitize());
    this.app.use(hpp()); // Prevent HTTP Parameter Pollution

    // Compression
    this.app.use(compression({
      level: 6,
      threshold: 1024,
      filter: (req, res) => {
        if (req.headers['x-no-compression']) {
          return false;
        }
        return compression.filter(req, res);
      }
    }));

    // Logging middleware
    if (process.env.NODE_ENV !== 'test') {
      this.app.use(morgan('combined', {
        stream: {
          write: (message) => logger.info(message.trim())
        }
      }));
    }

    // Custom middleware for request tracking
    this.app.use((req, res, next) => {
      req.requestId = require('crypto').randomUUID();
      req.startTime = Date.now();
      
      // Add request ID to response headers
      res.setHeader('X-Request-ID', req.requestId);
      
      next();
    });

    // User activity tracking middleware
    this.app.use(async (req, res, next) => {
      if (req.user) {
        try {
          // Update last activity
          await mongoose.model('User').findByIdAndUpdate(
            req.user.id,
            { 
              lastActivity: new Date(),
              ipAddress: req.ip,
              userAgent: req.get('User-Agent')
            }
          );
        } catch (error) {
          logger.warn('Failed to update user activity:', error);
        }
      }
      next();
    });

    // API usage tracking middleware
    this.app.use('/api/', async (req, res, next) => {
      if (req.user && req.user.apiUsage) {
        try {
          await mongoose.model('User').findByIdAndUpdate(
            req.user.id,
            { $inc: { 'apiUsage.requestsThisMonth': 1 } }
          );
        } catch (error) {
          logger.warn('Failed to update API usage:', error);
        }
      }
      next();
    });
  }

  /**
   * Initialize application routes
   */
  initializeRoutes() {
    // Health check routes (no auth required)
    this.app.use('/api/health', healthRoutes);

    // Webhook routes (special handling for payment processors)
    this.app.use('/api/webhooks', webhookRoutes);

    // Authentication routes
    this.app.use('/api/auth', authRoutes);

    // Protected routes - require authentication
    this.app.use('/api/users', authMiddleware, userRoutes);
    this.app.use('/api/targets', authMiddleware, targetRoutes);
    this.app.use('/api/scans', authMiddleware, scanRoutes);
    this.app.use('/api/reports', authMiddleware, reportRoutes);
    this.app.use('/api/phishing', authMiddleware, phishingRoutes);
    this.app.use('/api/billing', authMiddleware, billingRoutes);
    this.app.use('/api/analytics', authMiddleware, analyticsRoutes);

    // API routes for DevSecOps integration
    this.app.use('/api/v1', apiRoutes);

    // Serve static files (reports, uploads)
    this.app.use('/uploads', express.static('uploads'));
    this.app.use('/reports', express.static('reports'));

    // API documentation route
    this.app.get('/api', (req, res) => {
      res.json({
        name: 'Cybersecurity Risk Platform API',
        version: '1.0.0',
        description: 'AI-Powered Cybersecurity Risk Simulation Platform',
        endpoints: {
          authentication: '/api/auth',
          users: '/api/users',
          targets: '/api/targets',
          scans: '/api/scans',
          reports: '/api/reports',
          phishing: '/api/phishing',
          billing: '/api/billing',
          analytics: '/api/analytics',
          webhooks: '/api/webhooks',
          health: '/api/health'
        },
        documentation: '/api/docs',
        status: 'operational'
      });
    });

    // Catch-all route for undefined API endpoints
    this.app.all('/api/*', notFoundHandler);

    // Frontend route handler (for production)
    if (process.env.NODE_ENV === 'production') {
      const path = require('path');
      this.app.use(express.static(path.join(__dirname, '../../frontend/build')));
      
      this.app.get('*', (req, res) => {
        res.sendFile(path.join(__dirname, '../../frontend/build/index.html'));
      });
    }
  }

  /**
   * Initialize error handling middleware
   */
  initializeErrorHandling() {
    // Global error handler
    this.app.use(errorHandler);

    // Handle unhandled promise rejections
    process.on('unhandledRejection', (reason, promise) => {
      logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
      // Close server gracefully
      this.gracefulShutdown();
    });

    // Handle uncaught exceptions
    process.on('uncaughtException', (error) => {
      logger.error('Uncaught Exception:', error);
      // Close server gracefully
      this.gracefulShutdown();
    });

    // Handle SIGTERM signal
    process.on('SIGTERM', () => {
      logger.info('SIGTERM received, shutting down gracefully');
      this.gracefulShutdown();
    });

    // Handle SIGINT signal (Ctrl+C)
    process.on('SIGINT', () => {
      logger.info('SIGINT received, shutting down gracefully');
      this.gracefulShutdown();
    });
  }

  /**
   * Initialize Socket.IO for real-time communication
   */
  initializeSocket() {
    // Socket.IO middleware for authentication
    this.io.use(async (socket, next) => {
      try {
        const token = socket.handshake.auth.token || socket.handshake.headers.authorization;
        if (!token) {
          return next(new Error('Authentication token required'));
        }

        const jwt = require('jsonwebtoken');
        const decoded = jwt.verify(token.replace('Bearer ', ''), process.env.JWT_SECRET);
        
        const User = mongoose.model('User');
        const user = await User.findById(decoded.id);
        
        if (!user || !user.isActive) {
          return next(new Error('Invalid authentication token'));
        }

        socket.user = user;
        next();
      } catch (error) {
        next(new Error('Authentication failed'));
      }
    });

    // Setup socket handlers
    setupSocketHandlers(this.io);

    logger.info('Socket.IO initialized');
  }

  /**
   * Connect to MongoDB database
   */
  async connectDatabase() {
    try {
      const mongoURI = process.env.MONGODB_URI || 'mongodb://localhost:27017/cybersecurity_platform';
      
      await mongoose.connect(mongoURI, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
        maxPoolSize: 10,
        serverSelectionTimeoutMS: 5000,
        socketTimeoutMS: 45000,
        bufferMaxEntries: 0,
        bufferCommands: false
      });

      logger.info('Connected to MongoDB');

      // Handle MongoDB connection events
      mongoose.connection.on('error', (error) => {
        logger.error('MongoDB connection error:', error);
      });

      mongoose.connection.on('disconnected', () => {
        logger.warn('MongoDB disconnected');
      });

      mongoose.connection.on('reconnected', () => {
        logger.info('MongoDB reconnected');
      });

    } catch (error) {
      logger.error('Failed to connect to MongoDB:', error);
      process.exit(1);
    }
  }

  /**
   * Start the server
   */
  async start() {
    try {
      // Connect to database
      await this.connectDatabase();

      // Initialize background services
      await this.initializeBackgroundServices();

      // Start the server
      const PORT = process.env.API_PORT || 3001;
      this.server.listen(PORT, () => {
        logger.info(`🚀 Cybersecurity Platform API server running on port ${PORT}`);
        logger.info(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
        logger.info(`🔗 API Documentation: http://localhost:${PORT}/api`);
        
        if (process.env.NODE_ENV === 'development') {
          logger.info(`🎯 GraphQL Playground: http://localhost:${PORT}/graphql`);
        }
      });

    } catch (error) {
      logger.error('Failed to start server:', error);
      process.exit(1);
    }
  }

  /**
   * Initialize background services and job processors
   */
  async initializeBackgroundServices() {
    try {
      // Initialize scan queue processor
      const scanQueueService = require('./services/scanQueueService');
      await scanQueueService.initialize(this.redis);

      // Initialize report generation service
      const reportService = require('./services/reportService');
      await reportService.initialize();

      // Initialize notification service
      const notificationService = require('./services/notificationService');
      await notificationService.initialize();

      // Initialize ML prediction service
      const mlService = require('./services/mlService');
      await mlService.initialize();

      // Setup cron jobs
      const cronService = require('./services/cronService');
      cronService.setupJobs();

      logger.info('Background services initialized');
    } catch (error) {
      logger.error('Failed to initialize background services:', error);
      throw error;
    }
  }

  /**
   * Graceful shutdown handler
   */
  async gracefulShutdown() {
    logger.info('Starting graceful shutdown...');

    try {
      // Close server
      this.server.close(() => {
        logger.info('HTTP server closed');
      });

      // Close Socket.IO
      this.io.close(() => {
        logger.info('Socket.IO server closed');
      });

      // Close database connection
      await mongoose.connection.close();
      logger.info('Database connection closed');

      // Close Redis connection
      if (this.redis) {
        await this.redis.quit();
        logger.info('Redis connection closed');
      }

      logger.info('Graceful shutdown completed');
      process.exit(0);
    } catch (error) {
      logger.error('Error during graceful shutdown:', error);
      process.exit(1);
    }
  }

  /**
   * Get Express app instance (for testing)
   */
  getApp() {
    return this.app;
  }

  /**
   * Get Socket.IO instance
   */
  getIO() {
    return this.io;
  }
}

// Create and start the application
const app = new CybersecurityPlatformApp();

// Start the server if this file is run directly
if (require.main === module) {
  app.start().catch((error) => {
    logger.error('Failed to start application:', error);
    process.exit(1);
  });
}

module.exports = app;