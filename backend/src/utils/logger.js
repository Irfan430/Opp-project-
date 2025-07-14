const winston = require('winston');
const path = require('path');

/**
 * Custom log format for better readability
 */
const logFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.errors({ stack: true }),
  winston.format.json(),
  winston.format.prettyPrint()
);

/**
 * Console format for development
 */
const consoleFormat = winston.format.combine(
  winston.format.colorize(),
  winston.format.timestamp({ format: 'HH:mm:ss' }),
  winston.format.printf(({ timestamp, level, message, stack }) => {
    return stack 
      ? `${timestamp} [${level}]: ${message}\n${stack}`
      : `${timestamp} [${level}]: ${message}`;
  })
);

/**
 * Create logger instance with multiple transports
 */
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: logFormat,
  defaultMeta: { 
    service: 'cybersec-platform',
    version: process.env.npm_package_version || '1.0.0'
  },
  transports: [
    // Console transport for development
    new winston.transports.Console({
      format: process.env.NODE_ENV === 'production' ? logFormat : consoleFormat,
      level: process.env.NODE_ENV === 'production' ? 'info' : 'debug'
    })
  ],
  // Don't exit on handled exceptions
  exitOnError: false
});

// Add file transports in production or when LOG_FILE is specified
if (process.env.NODE_ENV === 'production' || process.env.LOG_FILE) {
  const logDir = path.dirname(process.env.LOG_FILE || './logs/app.log');
  
  // Ensure log directory exists
  require('fs').mkdirSync(logDir, { recursive: true });
  
  // Error log file
  logger.add(new winston.transports.File({
    filename: process.env.LOG_FILE || './logs/error.log',
    level: 'error',
    maxsize: 10485760, // 10MB
    maxFiles: 5,
    tailable: true
  }));
  
  // Combined log file
  logger.add(new winston.transports.File({
    filename: process.env.LOG_FILE || './logs/combined.log',
    maxsize: 10485760, // 10MB
    maxFiles: 10,
    tailable: true
  }));
}

// Handle exceptions and rejections
logger.exceptions.handle(
  new winston.transports.Console({
    format: consoleFormat
  })
);

logger.rejections.handle(
  new winston.transports.Console({
    format: consoleFormat
  })
);

/**
 * Create child logger with additional metadata
 * @param {Object} metadata - Additional metadata to include in logs
 * @returns {Object} Child logger instance
 */
logger.child = (metadata) => {
  return winston.createLogger({
    level: logger.level,
    format: logger.format,
    defaultMeta: { ...logger.defaultMeta, ...metadata },
    transports: logger.transports
  });
};

/**
 * Log request information
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {number} duration - Request duration in milliseconds
 */
logger.logRequest = (req, res, duration) => {
  const logData = {
    method: req.method,
    url: req.originalUrl,
    statusCode: res.statusCode,
    duration: `${duration}ms`,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    requestId: req.requestId
  };
  
  if (req.user) {
    logData.userId = req.user.id;
    logData.userEmail = req.user.email;
  }
  
  const level = res.statusCode >= 400 ? 'warn' : 'info';
  logger.log(level, 'HTTP Request', logData);
};

/**
 * Log security events
 * @param {string} event - Security event type
 * @param {Object} details - Event details
 * @param {Object} req - Express request object
 */
logger.logSecurity = (event, details, req) => {
  const securityData = {
    event,
    details,
    ip: req?.ip,
    userAgent: req?.get('User-Agent'),
    requestId: req?.requestId,
    timestamp: new Date().toISOString()
  };
  
  if (req?.user) {
    securityData.userId = req.user.id;
    securityData.userEmail = req.user.email;
  }
  
  logger.warn('Security Event', securityData);
};

/**
 * Log performance metrics
 * @param {string} operation - Operation name
 * @param {number} duration - Operation duration in milliseconds
 * @param {Object} metadata - Additional metadata
 */
logger.logPerformance = (operation, duration, metadata = {}) => {
  logger.info('Performance Metric', {
    operation,
    duration: `${duration}ms`,
    ...metadata
  });
};

/**
 * Log database operations
 * @param {string} operation - Database operation
 * @param {string} collection - Database collection
 * @param {number} duration - Operation duration
 * @param {Object} metadata - Additional metadata
 */
logger.logDatabase = (operation, collection, duration, metadata = {}) => {
  logger.debug('Database Operation', {
    operation,
    collection,
    duration: `${duration}ms`,
    ...metadata
  });
};

/**
 * Create structured error log
 * @param {Error} error - Error object
 * @param {Object} context - Additional context
 */
logger.logError = (error, context = {}) => {
  logger.error('Application Error', {
    message: error.message,
    stack: error.stack,
    code: error.code,
    ...context
  });
};

// Export logger instance
module.exports = logger;