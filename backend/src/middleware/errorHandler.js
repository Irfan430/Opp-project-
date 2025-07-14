const logger = require('../utils/logger');

/**
 * Custom Application Error class
 */
class AppError extends Error {
  constructor(message, statusCode = 500, code = null) {
    super(message);
    this.statusCode = statusCode;
    this.status = `${statusCode}`.startsWith('4') ? 'fail' : 'error';
    this.isOperational = true;
    this.code = code;

    Error.captureStackTrace(this, this.constructor);
  }
}

/**
 * Handle MongoDB Cast Errors (Invalid ObjectId)
 */
const handleCastErrorDB = (err) => {
  const message = `Invalid ${err.path}: ${err.value}`;
  return new AppError(message, 400, 'INVALID_ID');
};

/**
 * Handle MongoDB Duplicate Field Errors
 */
const handleDuplicateFieldsDB = (err) => {
  const value = err.errmsg.match(/(["'])(\\?.)*?\1/)[0];
  const message = `Duplicate field value: ${value}. Please use another value!`;
  return new AppError(message, 400, 'DUPLICATE_FIELD');
};

/**
 * Handle MongoDB Validation Errors
 */
const handleValidationErrorDB = (err) => {
  const errors = Object.values(err.errors).map(el => el.message);
  const message = `Invalid input data. ${errors.join('. ')}`;
  return new AppError(message, 400, 'VALIDATION_ERROR');
};

/**
 * Handle JWT Errors
 */
const handleJWTError = () =>
  new AppError('Invalid token. Please log in again!', 401, 'INVALID_TOKEN');

/**
 * Handle JWT Expired Errors
 */
const handleJWTExpiredError = () =>
  new AppError('Your token has expired! Please log in again.', 401, 'TOKEN_EXPIRED');

/**
 * Handle Stripe Errors
 */
const handleStripeError = (err) => {
  let message = 'Payment processing error';
  let statusCode = 400;
  
  switch (err.type) {
    case 'StripeCardError':
      message = err.message;
      statusCode = 402;
      break;
    case 'StripeRateLimitError':
      message = 'Too many requests made to the API too quickly';
      statusCode = 429;
      break;
    case 'StripeInvalidRequestError':
      message = 'Invalid parameters were supplied to Stripe API';
      statusCode = 400;
      break;
    case 'StripeAPIError':
      message = 'An error occurred internally with Stripe API';
      statusCode = 500;
      break;
    case 'StripeConnectionError':
      message = 'Network communication with Stripe failed';
      statusCode = 500;
      break;
    case 'StripeAuthenticationError':
      message = 'Authentication with Stripe API failed';
      statusCode = 401;
      break;
    default:
      message = err.message || 'Payment processing error';
  }
  
  return new AppError(message, statusCode, 'PAYMENT_ERROR');
};

/**
 * Handle Redis Errors
 */
const handleRedisError = (err) => {
  logger.error('Redis error:', err);
  return new AppError('Cache service temporarily unavailable', 503, 'CACHE_ERROR');
};

/**
 * Handle Rate Limit Errors
 */
const handleRateLimitError = () =>
  new AppError('Too many requests, please try again later', 429, 'RATE_LIMIT_EXCEEDED');

/**
 * Send error response in development
 */
const sendErrorDev = (err, req, res) => {
  // API errors
  if (req.originalUrl.startsWith('/api')) {
    return res.status(err.statusCode).json({
      status: err.status,
      error: err,
      message: err.message,
      stack: err.stack,
      code: err.code,
      requestId: req.requestId
    });
  }

  // Rendered website errors
  logger.error('ERROR 💥', err);
  return res.status(err.statusCode).render('error', {
    title: 'Something went wrong!',
    msg: err.message
  });
};

/**
 * Send error response in production
 */
const sendErrorProd = (err, req, res) => {
  // API errors
  if (req.originalUrl.startsWith('/api')) {
    // Operational, trusted error: send message to client
    if (err.isOperational) {
      return res.status(err.statusCode).json({
        status: err.status,
        message: err.message,
        code: err.code,
        requestId: req.requestId
      });
    }

    // Programming or unknown error: don't leak error details
    logger.error('ERROR 💥', err);
    return res.status(500).json({
      status: 'error',
      message: 'Something went wrong!',
      requestId: req.requestId
    });
  }

  // Rendered website errors
  if (err.isOperational) {
    return res.status(err.statusCode).render('error', {
      title: 'Something went wrong!',
      msg: err.message
    });
  }

  logger.error('ERROR 💥', err);
  return res.status(err.statusCode).render('error', {
    title: 'Something went wrong!',
    msg: 'Please try again later.'
  });
};

/**
 * Global error handling middleware
 */
const errorHandler = (err, req, res, next) => {
  err.statusCode = err.statusCode || 500;
  err.status = err.status || 'error';

  // Log the error
  logger.logError(err, {
    requestId: req.requestId,
    url: req.originalUrl,
    method: req.method,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    userId: req.user?.id,
    body: req.method !== 'GET' ? req.body : undefined
  });

  if (process.env.NODE_ENV === 'development') {
    sendErrorDev(err, req, res);
  } else {
    let error = { ...err };
    error.message = err.message;

    // Handle specific error types
    if (error.name === 'CastError') error = handleCastErrorDB(error);
    if (error.code === 11000) error = handleDuplicateFieldsDB(error);
    if (error.name === 'ValidationError') error = handleValidationErrorDB(error);
    if (error.name === 'JsonWebTokenError') error = handleJWTError();
    if (error.name === 'TokenExpiredError') error = handleJWTExpiredError();
    if (error.type && error.type.startsWith('Stripe')) error = handleStripeError(error);
    if (error.name === 'RedisError') error = handleRedisError(error);
    if (error.code === 'RATE_LIMIT_EXCEEDED') error = handleRateLimitError();

    sendErrorProd(error, req, res);
  }
};

/**
 * Async error wrapper
 * Catches async errors and passes them to the error handler
 */
const catchAsync = (fn) => {
  return (req, res, next) => {
    fn(req, res, next).catch(next);
  };
};

/**
 * Handle 404 errors for API routes
 */
const handleNotFound = (req, res, next) => {
  const err = new AppError(`Can't find ${req.originalUrl} on this server!`, 404, 'NOT_FOUND');
  next(err);
};

/**
 * Validation error helper
 */
const createValidationError = (message, field = null) => {
  const error = new AppError(message, 400, 'VALIDATION_ERROR');
  if (field) error.field = field;
  return error;
};

/**
 * Authorization error helper
 */
const createAuthError = (message = 'Not authorized') => {
  return new AppError(message, 403, 'AUTHORIZATION_ERROR');
};

/**
 * Authentication error helper
 */
const createAuthenticationError = (message = 'Authentication required') => {
  return new AppError(message, 401, 'AUTHENTICATION_ERROR');
};

/**
 * Resource not found error helper
 */
const createNotFoundError = (resource = 'Resource') => {
  return new AppError(`${resource} not found`, 404, 'NOT_FOUND');
};

/**
 * Conflict error helper
 */
const createConflictError = (message) => {
  return new AppError(message, 409, 'CONFLICT_ERROR');
};

/**
 * Rate limit error helper
 */
const createRateLimitError = (message = 'Too many requests') => {
  return new AppError(message, 429, 'RATE_LIMIT_EXCEEDED');
};

/**
 * Service unavailable error helper
 */
const createServiceUnavailableError = (message = 'Service temporarily unavailable') => {
  return new AppError(message, 503, 'SERVICE_UNAVAILABLE');
};

module.exports = {
  AppError,
  errorHandler,
  catchAsync,
  handleNotFound,
  createValidationError,
  createAuthError,
  createAuthenticationError,
  createNotFoundError,
  createConflictError,
  createRateLimitError,
  createServiceUnavailableError
};