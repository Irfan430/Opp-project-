const jwt = require('jsonwebtoken');
const { promisify } = require('util');
const User = require('../models/User');
const { AppError, catchAsync } = require('./errorHandler');
const logger = require('../utils/logger');

/**
 * Authentication middleware
 * Verifies JWT token and sets req.user
 */
const authenticate = catchAsync(async (req, res, next) => {
  // 1) Getting token and check if it's there
  let token;
  
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  } else if (req.cookies?.jwt) {
    token = req.cookies.jwt;
  }

  if (!token) {
    logger.logSecurity('authentication_failed', { reason: 'no_token' }, req);
    return next(new AppError('You are not logged in! Please log in to get access.', 401, 'AUTHENTICATION_REQUIRED'));
  }

  try {
    // 2) Verification token
    const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

    // 3) Check if user still exists
    const currentUser = await User.findById(decoded.id).select('+passwordChangedAt');
    if (!currentUser) {
      logger.logSecurity('authentication_failed', { reason: 'user_not_found', userId: decoded.id }, req);
      return next(new AppError('The user belonging to this token does no longer exist.', 401, 'USER_NOT_FOUND'));
    }

    // 4) Check if user is active
    if (!currentUser.isActive) {
      logger.logSecurity('authentication_failed', { reason: 'user_inactive', userId: decoded.id }, req);
      return next(new AppError('Your account has been deactivated. Please contact support.', 401, 'ACCOUNT_INACTIVE'));
    }

    // 5) Check if user changed password after the token was issued
    if (currentUser.changedPasswordAfter && currentUser.changedPasswordAfter(decoded.iat)) {
      logger.logSecurity('authentication_failed', { reason: 'password_changed', userId: decoded.id }, req);
      return next(new AppError('User recently changed password! Please log in again.', 401, 'PASSWORD_CHANGED'));
    }

    // 6) Check account lock status
    if (currentUser.isLocked) {
      logger.logSecurity('authentication_failed', { reason: 'account_locked', userId: decoded.id }, req);
      return next(new AppError('Account temporarily locked due to too many failed login attempts.', 401, 'ACCOUNT_LOCKED'));
    }

    // 7) Check subscription status for non-admin users
    if (currentUser.role !== 'admin' && currentUser.subscription.status !== 'active') {
      return next(new AppError('Your subscription is not active. Please update your billing information.', 402, 'SUBSCRIPTION_INACTIVE'));
    }

    // GRANT ACCESS TO PROTECTED ROUTE
    req.user = currentUser;
    res.locals.user = currentUser;
    next();
  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      logger.logSecurity('authentication_failed', { reason: 'invalid_token', error: error.message }, req);
      return next(new AppError('Invalid token. Please log in again!', 401, 'INVALID_TOKEN'));
    } else if (error.name === 'TokenExpiredError') {
      logger.logSecurity('authentication_failed', { reason: 'token_expired', error: error.message }, req);
      return next(new AppError('Your token has expired! Please log in again.', 401, 'TOKEN_EXPIRED'));
    } else {
      logger.logSecurity('authentication_error', { error: error.message }, req);
      return next(new AppError('Authentication failed', 401, 'AUTHENTICATION_ERROR'));
    }
  }
});

/**
 * Authorization middleware factory
 * Restricts access based on user roles
 */
const authorize = (...roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return next(new AppError('Authentication required', 401, 'AUTHENTICATION_REQUIRED'));
    }

    if (!roles.includes(req.user.role)) {
      logger.logSecurity('authorization_failed', { 
        userId: req.user.id, 
        userRole: req.user.role, 
        requiredRoles: roles 
      }, req);
      return next(new AppError('You do not have permission to perform this action', 403, 'INSUFFICIENT_PERMISSIONS'));
    }

    next();
  };
};

/**
 * Permission-based authorization middleware
 * Restricts access based on specific permissions
 */
const requirePermission = (...permissions) => {
  return (req, res, next) => {
    if (!req.user) {
      return next(new AppError('Authentication required', 401, 'AUTHENTICATION_REQUIRED'));
    }

    const userPermissions = req.user.permissions || [];
    const hasPermission = permissions.some(permission => userPermissions.includes(permission));

    if (!hasPermission && req.user.role !== 'admin') {
      logger.logSecurity('permission_denied', { 
        userId: req.user.id, 
        userPermissions: userPermissions, 
        requiredPermissions: permissions 
      }, req);
      return next(new AppError('You do not have the required permissions', 403, 'INSUFFICIENT_PERMISSIONS'));
    }

    next();
  };
};

/**
 * Resource ownership verification middleware
 * Ensures user can only access their own resources
 */
const requireOwnership = (resourceModel, resourceIdParam = 'id', ownerField = 'owner') => {
  return catchAsync(async (req, res, next) => {
    if (!req.user) {
      return next(new AppError('Authentication required', 401, 'AUTHENTICATION_REQUIRED'));
    }

    // Admin users can access all resources
    if (req.user.role === 'admin') {
      return next();
    }

    const resourceId = req.params[resourceIdParam];
    const resource = await resourceModel.findById(resourceId);

    if (!resource) {
      return next(new AppError('Resource not found', 404, 'RESOURCE_NOT_FOUND'));
    }

    // Check ownership
    const ownerId = resource[ownerField];
    if (!ownerId || ownerId.toString() !== req.user.id.toString()) {
      logger.logSecurity('ownership_violation', { 
        userId: req.user.id, 
        resourceId: resourceId, 
        resourceType: resourceModel.modelName 
      }, req);
      return next(new AppError('You can only access your own resources', 403, 'ACCESS_DENIED'));
    }

    // Attach resource to request for further use
    req.resource = resource;
    next();
  });
};

/**
 * Organization-based access control
 * Ensures user can only access resources from their organization
 */
const requireOrganizationAccess = (resourceModel, resourceIdParam = 'id') => {
  return catchAsync(async (req, res, next) => {
    if (!req.user) {
      return next(new AppError('Authentication required', 401, 'AUTHENTICATION_REQUIRED'));
    }

    // Admin users can access all resources
    if (req.user.role === 'admin') {
      return next();
    }

    const resourceId = req.params[resourceIdParam];
    const resource = await resourceModel.findById(resourceId);

    if (!resource) {
      return next(new AppError('Resource not found', 404, 'RESOURCE_NOT_FOUND'));
    }

    // Check organization access
    if (resource.organization && resource.organization !== req.user.organization) {
      logger.logSecurity('organization_access_violation', { 
        userId: req.user.id, 
        userOrg: req.user.organization,
        resourceOrg: resource.organization,
        resourceId: resourceId, 
        resourceType: resourceModel.modelName 
      }, req);
      return next(new AppError('You can only access resources from your organization', 403, 'ACCESS_DENIED'));
    }

    req.resource = resource;
    next();
  });
};

/**
 * API key authentication middleware
 * For DevSecOps integrations
 */
const authenticateApiKey = catchAsync(async (req, res, next) => {
  const apiKey = req.headers['x-api-key'] || req.query.apiKey;

  if (!apiKey) {
    return next(new AppError('API key required', 401, 'API_KEY_REQUIRED'));
  }

  // Find user by API key
  const user = await User.findOne({ 
    apiKey: apiKey,
    apiKeyExpires: { $gt: new Date() },
    isActive: true
  });

  if (!user) {
    logger.logSecurity('api_authentication_failed', { apiKey: apiKey.substring(0, 8) + '...' }, req);
    return next(new AppError('Invalid or expired API key', 401, 'INVALID_API_KEY'));
  }

  // Check API usage limits
  if (user.apiUsage.requestsThisMonth >= user.apiUsage.maxRequestsPerMonth) {
    logger.logSecurity('api_rate_limit_exceeded', { userId: user.id }, req);
    return next(new AppError('API usage limit exceeded', 429, 'API_LIMIT_EXCEEDED'));
  }

  req.user = user;
  next();
});

/**
 * Subscription tier validation middleware
 */
const requireSubscriptionTier = (...allowedTiers) => {
  return (req, res, next) => {
    if (!req.user) {
      return next(new AppError('Authentication required', 401, 'AUTHENTICATION_REQUIRED'));
    }

    const userTier = req.user.subscription?.plan || 'free';
    
    if (!allowedTiers.includes(userTier) && req.user.role !== 'admin') {
      return next(new AppError('This feature requires a higher subscription tier', 402, 'SUBSCRIPTION_UPGRADE_REQUIRED'));
    }

    next();
  };
};

/**
 * Usage limits validation middleware
 */
const checkUsageLimits = (resourceType) => {
  return catchAsync(async (req, res, next) => {
    if (!req.user) {
      return next(new AppError('Authentication required', 401, 'AUTHENTICATION_REQUIRED'));
    }

    // Admin users bypass limits
    if (req.user.role === 'admin') {
      return next();
    }

    const hasCapacity = User.checkSubscriptionLimits(req.user, resourceType);
    
    if (!hasCapacity) {
      const limitType = {
        targets: 'target limit',
        scans: 'monthly scan limit',
        reports: 'report limit'
      }[resourceType] || 'usage limit';

      return next(new AppError(`You have reached your ${limitType}. Please upgrade your subscription.`, 402, 'USAGE_LIMIT_EXCEEDED'));
    }

    next();
  });
};

/**
 * Optional authentication middleware
 * Sets req.user if token is valid, but doesn't require authentication
 */
const optionalAuth = catchAsync(async (req, res, next) => {
  let token;
  
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  } else if (req.cookies?.jwt) {
    token = req.cookies.jwt;
  }

  if (token) {
    try {
      const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);
      const currentUser = await User.findById(decoded.id);
      
      if (currentUser && currentUser.isActive) {
        req.user = currentUser;
        res.locals.user = currentUser;
      }
    } catch (error) {
      // Token invalid, but continue without authentication
      logger.debug('Optional auth failed:', error.message);
    }
  }

  next();
});

module.exports = {
  authenticate,
  authorize,
  requirePermission,
  requireOwnership,
  requireOrganizationAccess,
  authenticateApiKey,
  requireSubscriptionTier,
  checkUsageLimits,
  optionalAuth
};