/**
 * Winston Logger Configuration
 */

const winston = require('winston');
const path = require('path');

// Define log levels
const levels = {
  error: 0,
  warn: 1,
  info: 2,
  http: 3,
  debug: 4,
};

// Define colors for each level
const colors = {
  error: 'red',
  warn: 'yellow',
  info: 'green',
  http: 'magenta',
  debug: 'white',
};

// Tell winston that you want to link the colors
winston.addColors(colors);

// Define which level to log based on environment
const level = () => {
  const env = process.env.NODE_ENV || 'development';
  const isDevelopment = env === 'development';
  return isDevelopment ? 'debug' : 'warn';
};

// Create custom format
const logFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss:ms' }),
  winston.format.errors({ stack: true }),
  winston.format.colorize({ all: true }),
  winston.format.printf(
    (info) => `${info.timestamp} ${info.level}: ${info.message}`
  ),
);

// Define transports
const transports = [
  // Console transport
  new winston.transports.Console({
    format: logFormat,
  }),
];

// Add file transport for production
if (process.env.NODE_ENV === 'production') {
  const logDir = process.env.LOG_FILE_PATH || './logs';
  
  transports.push(
    // Error log file
    new winston.transports.File({
      filename: path.join(logDir, 'error.log'),
      level: 'error',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json()
      ),
      maxsize: 5242880, // 5MB
      maxFiles: 5,
    }),
    
    // Combined log file
    new winston.transports.File({
      filename: path.join(logDir, 'combined.log'),
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json()
      ),
      maxsize: 5242880, // 5MB
      maxFiles: 5,
    })
  );
}

// Create the logger
const logger = winston.createLogger({
  level: level(),
  levels,
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  transports,
  // Handle uncaught exceptions
  exceptionHandlers: [
    new winston.transports.Console({
      format: logFormat,
    }),
  ],
  // Handle unhandled promise rejections
  rejectionHandlers: [
    new winston.transports.Console({
      format: logFormat,
    }),
  ],
});

// Extend logger with security-specific methods
logger.security = (message, meta = {}) => {
  logger.warn(`[SECURITY] ${message}`, {
    ...meta,
    type: 'security',
    timestamp: new Date().toISOString()
  });
};

logger.audit = (message, meta = {}) => {
  logger.info(`[AUDIT] ${message}`, {
    ...meta,
    type: 'audit',
    timestamp: new Date().toISOString()
  });
};

logger.performance = (message, meta = {}) => {
  logger.info(`[PERFORMANCE] ${message}`, {
    ...meta,
    type: 'performance',
    timestamp: new Date().toISOString()
  });
};

module.exports = logger;