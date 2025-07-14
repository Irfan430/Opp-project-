/**
 * Authentication and Authorization Middleware
 */

const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { AppError, catchAsync } = require('./errorHandler');
const { getRedisClient } = require('../config/redis');
const logger = require('../config/logger');

/**
 * Verify JWT token and authenticate user
 */
const authenticate = catchAsync(async (req, res, next) => {
  // Get token from header
  let token;
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  } else if (req.headers['x-api-key']) {
    // Support API key authentication for CI/CD
    token = req.headers['x-api-key'];
  }

  if (!token) {
    return next(new AppError('Access denied. No token provided.', 401));
  }

  try {
    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Check if token is blacklisted (for logout)
    const redisClient = getRedisClient();
    const isBlacklisted = await redisClient.get(`blacklist:${token}`);
    if (isBlacklisted) {
      return next(new AppError('Token has been invalidated', 401));
    }

    // Check if user still exists
    const user = await User.findById(decoded.id).select('+active');
    if (!user) {
      return next(new AppError('The user belonging to this token no longer exists', 401));
    }

    // Check if user is active
    if (!user.active) {
      return next(new AppError('Your account has been deactivated', 401));
    }

    // Check if user changed password after token was issued
    if (user.changedPasswordAfter(decoded.iat)) {
      return next(new AppError('User recently changed password. Please log in again.', 401));
    }

    // Update last active timestamp
    user.lastActive = new Date();
    await user.save({ validateBeforeSave: false });

    // Grant access to protected route
    req.user = user;
    
    // Log successful authentication
    logger.audit('User authenticated', {
      userId: user._id,
      email: user.email,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    next();
  } catch (error) {
    logger.security('Authentication failed', {
      token: token.substring(0, 10) + '...',
      error: error.message,
      ip: req.ip
    });
    
    if (error.name === 'TokenExpiredError') {
      return next(new AppError('Your token has expired! Please log in again.', 401));
    }
    return next(new AppError('Invalid token', 401));
  }
});

/**
 * Authorize user based on roles
 */
const authorize = (...roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return next(new AppError('You are not authenticated', 401));
    }

    if (!roles.includes(req.user.role)) {
      logger.security('Unauthorized access attempt', {
        userId: req.user._id,
        userRole: req.user.role,
        requiredRoles: roles,
        endpoint: req.originalUrl,
        ip: req.ip
      });
      
      return next(new AppError('You do not have permission to perform this action', 403));
    }

    next();
  };
};

/**
 * API Key authentication for CI/CD integration
 */
const authenticateApiKey = catchAsync(async (req, res, next) => {
  const apiKey = req.headers['x-api-key'];
  
  if (!apiKey) {
    return next(new AppError('API key required', 401));
  }

  // Find user by API key
  const user = await User.findOne({ 
    apiKey: apiKey,
    active: true 
  });

  if (!user) {
    logger.security('Invalid API key used', {
      apiKey: apiKey.substring(0, 10) + '...',
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });
    return next(new AppError('Invalid API key', 401));
  }

  // Check if API key is expired
  if (user.apiKeyExpiry && user.apiKeyExpiry < new Date()) {
    return next(new AppError('API key has expired', 401));
  }

  req.user = user;
  
  logger.audit('API key authentication successful', {
    userId: user._id,
    email: user.email,
    ip: req.ip
  });

  next();
});

/**
 * Rate limiting per user
 */
const rateLimitPerUser = (maxRequests = 100, windowMs = 15 * 60 * 1000) => {
  return catchAsync(async (req, res, next) => {
    if (!req.user) {
      return next();
    }

    const redisClient = getRedisClient();
    const key = `rateLimit:${req.user._id}`;
    
    const requests = await redisClient.incr(key);
    
    if (requests === 1) {
      await redisClient.expire(key, Math.ceil(windowMs / 1000));
    }

    if (requests > maxRequests) {
      const ttl = await redisClient.ttl(key);
      
      logger.security('Rate limit exceeded', {
        userId: req.user._id,
        requests,
        limit: maxRequests,
        ip: req.ip
      });

      return res.status(429).json({
        success: false,
        message: 'Too many requests',
        retryAfter: ttl
      });
    }

    req.rateLimit = {
      limit: maxRequests,
      current: requests,
      remaining: maxRequests - requests
    };

    next();
  });
};

/**
 * Check if user owns the resource
 */
const checkOwnership = (model, field = 'user') => {
  return catchAsync(async (req, res, next) => {
    const Model = require(`../models/${model}`);
    const resource = await Model.findById(req.params.id);

    if (!resource) {
      return next(new AppError(`${model} not found`, 404));
    }

    // Admin can access all resources
    if (req.user.role === 'admin') {
      req.resource = resource;
      return next();
    }

    // Check ownership
    const resourceUserId = resource[field]?.toString() || resource[field];
    if (resourceUserId !== req.user._id.toString()) {
      logger.security('Unauthorized resource access attempt', {
        userId: req.user._id,
        resourceId: req.params.id,
        resourceType: model,
        ip: req.ip
      });
      
      return next(new AppError('You can only access your own resources', 403));
    }

    req.resource = resource;
    next();
  });
};

/**
 * Subscription-based access control
 */
const requireSubscription = (requiredPlan = 'basic') => {
  return (req, res, next) => {
    if (!req.user.subscription || !req.user.subscription.active) {
      return next(new AppError('Active subscription required', 402));
    }

    const planHierarchy = { basic: 1, pro: 2, enterprise: 3 };
    const userPlanLevel = planHierarchy[req.user.subscription.plan] || 0;
    const requiredPlanLevel = planHierarchy[requiredPlan] || 0;

    if (userPlanLevel < requiredPlanLevel) {
      return next(new AppError(`${requiredPlan} subscription required`, 402));
    }

    next();
  };
};

module.exports = {
  authenticate,
  authorize,
  authenticateApiKey,
  rateLimitPerUser,
  checkOwnership,
  requireSubscription
};