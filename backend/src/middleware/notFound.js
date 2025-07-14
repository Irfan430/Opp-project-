const { AppError } = require('./errorHandler');

/**
 * 404 Not Found middleware for unmatched routes
 */
const notFoundHandler = (req, res, next) => {
  const err = new AppError(`Route ${req.originalUrl} not found`, 404, 'NOT_FOUND');
  next(err);
};

module.exports = notFoundHandler;