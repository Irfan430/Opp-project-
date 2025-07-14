const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

/**
 * User Schema for Cybersecurity Platform
 * Supports multi-tenancy, role-based access, and billing
 */
const userSchema = new mongoose.Schema({
  // Basic Information
  firstName: {
    type: String,
    required: [true, 'First name is required'],
    trim: true,
    maxlength: [50, 'First name cannot exceed 50 characters']
  },
  lastName: {
    type: String,
    required: [true, 'Last name is required'],
    trim: true,
    maxlength: [50, 'Last name cannot exceed 50 characters']
  },
  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
    lowercase: true,
    trim: true,
    match: [/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/, 'Please enter a valid email']
  },
  username: {
    type: String,
    required: [true, 'Username is required'],
    unique: true,
    trim: true,
    minlength: [3, 'Username must be at least 3 characters'],
    maxlength: [30, 'Username cannot exceed 30 characters']
  },
  password: {
    type: String,
    required: [true, 'Password is required'],
    minlength: [8, 'Password must be at least 8 characters'],
    select: false
  },

  // Role and Permissions
  role: {
    type: String,
    enum: ['admin', 'manager', 'viewer', 'user'],
    default: 'user'
  },
  permissions: [{
    type: String,
    enum: [
      'scan:create', 'scan:read', 'scan:update', 'scan:delete',
      'target:create', 'target:read', 'target:update', 'target:delete',
      'report:create', 'report:read', 'report:download',
      'user:create', 'user:read', 'user:update', 'user:delete',
      'billing:read', 'billing:update',
      'admin:access', 'analytics:read'
    ]
  }],

  // Organization/Company
  organization: {
    type: String,
    trim: true,
    maxlength: [100, 'Organization name cannot exceed 100 characters']
  },
  department: {
    type: String,
    trim: true,
    maxlength: [50, 'Department name cannot exceed 50 characters']
  },

  // Account Status
  isActive: {
    type: Boolean,
    default: true
  },
  isEmailVerified: {
    type: Boolean,
    default: false
  },
  emailVerificationToken: String,
  emailVerificationExpires: Date,

  // Security
  passwordResetToken: String,
  passwordResetExpires: Date,
  passwordChangedAt: Date,
  loginAttempts: {
    type: Number,
    default: 0
  },
  lockUntil: Date,
  twoFactorSecret: String,
  twoFactorEnabled: {
    type: Boolean,
    default: false
  },

  // Billing Information
  subscription: {
    plan: {
      type: String,
      enum: ['free', 'basic', 'professional', 'enterprise'],
      default: 'free'
    },
    status: {
      type: String,
      enum: ['active', 'inactive', 'cancelled', 'past_due'],
      default: 'active'
    },
    stripeCustomerId: String,
    stripeSubscriptionId: String,
    currentPeriodStart: Date,
    currentPeriodEnd: Date,
    cancelAtPeriodEnd: {
      type: Boolean,
      default: false
    }
  },

  // Usage Limits and Tracking
  limits: {
    maxTargets: {
      type: Number,
      default: 5
    },
    maxScansPerMonth: {
      type: Number,
      default: 10
    },
    maxReports: {
      type: Number,
      default: 5
    },
    maxUsers: {
      type: Number,
      default: 1
    }
  },
  usage: {
    currentTargets: {
      type: Number,
      default: 0
    },
    scansThisMonth: {
      type: Number,
      default: 0
    },
    currentReports: {
      type: Number,
      default: 0
    },
    totalScans: {
      type: Number,
      default: 0
    }
  },

  // Preferences
  preferences: {
    notifications: {
      email: {
        type: Boolean,
        default: true
      },
      telegram: {
        type: Boolean,
        default: false
      },
      slack: {
        type: Boolean,
        default: false
      }
    },
    alertThresholds: {
      critical: {
        type: Boolean,
        default: true
      },
      high: {
        type: Boolean,
        default: true
      },
      medium: {
        type: Boolean,
        default: false
      },
      low: {
        type: Boolean,
        default: false
      }
    },
    timezone: {
      type: String,
      default: 'UTC'
    },
    language: {
      type: String,
      default: 'en'
    }
  },

  // API Access
  apiKey: String,
  apiKeyExpires: Date,
  apiUsage: {
    requestsThisMonth: {
      type: Number,
      default: 0
    },
    maxRequestsPerMonth: {
      type: Number,
      default: 1000
    }
  },

  // Tracking
  lastLogin: Date,
  lastActivity: Date,
  ipAddress: String,
  userAgent: String
}, {
  timestamps: true,
  toJSON: {
    transform: function(doc, ret) {
      delete ret.password;
      delete ret.passwordResetToken;
      delete ret.emailVerificationToken;
      delete ret.twoFactorSecret;
      return ret;
    }
  }
});

// Indexes for performance
userSchema.index({ email: 1 });
userSchema.index({ username: 1 });
userSchema.index({ organization: 1 });
userSchema.index({ 'subscription.stripeCustomerId': 1 });
userSchema.index({ apiKey: 1 });

// Virtual for account lock status
userSchema.virtual('isLocked').get(function() {
  return !!(this.lockUntil && this.lockUntil > Date.now());
});

// Pre-save middleware to hash password
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  try {
    const salt = await bcrypt.genSalt(12);
    this.password = await bcrypt.hash(this.password, salt);
    this.passwordChangedAt = new Date();
    next();
  } catch (error) {
    next(error);
  }
});

// Instance method to check password
userSchema.methods.comparePassword = async function(candidatePassword) {
  if (!this.password) return false;
  return await bcrypt.compare(candidatePassword, this.password);
};

// Instance method to generate JWT token
userSchema.methods.generateToken = function() {
  return jwt.sign(
    { 
      id: this._id,
      email: this.email,
      role: this.role,
      permissions: this.permissions
    },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN || '7d' }
  );
};

// Instance method to generate refresh token
userSchema.methods.generateRefreshToken = function() {
  return jwt.sign(
    { id: this._id },
    process.env.REFRESH_TOKEN_SECRET,
    { expiresIn: process.env.REFRESH_TOKEN_EXPIRES_IN || '30d' }
  );
};

// Instance method to increment login attempts
userSchema.methods.incLoginAttempts = function() {
  // If we have a previous lock that has expired, restart at 1
  if (this.lockUntil && this.lockUntil < Date.now()) {
    return this.updateOne({
      $unset: { lockUntil: 1 },
      $set: { loginAttempts: 1 }
    });
  }
  
  const updates = { $inc: { loginAttempts: 1 } };
  
  // Lock account after 5 failed attempts for 2 hours
  if (this.loginAttempts + 1 >= 5 && !this.isLocked) {
    updates.$set = { lockUntil: Date.now() + 2 * 60 * 60 * 1000 }; // 2 hours
  }
  
  return this.updateOne(updates);
};

// Instance method to reset login attempts
userSchema.methods.resetLoginAttempts = function() {
  return this.updateOne({
    $unset: { loginAttempts: 1, lockUntil: 1 }
  });
};

// Static method to find by credentials
userSchema.statics.findByCredentials = async function(email, password) {
  const user = await this.findOne({ email }).select('+password');
  
  if (!user) {
    throw new Error('Invalid email or password');
  }
  
  if (user.isLocked) {
    throw new Error('Account temporarily locked due to too many failed login attempts');
  }
  
  const isMatch = await user.comparePassword(password);
  
  if (!isMatch) {
    await user.incLoginAttempts();
    throw new Error('Invalid email or password');
  }
  
  // Reset login attempts on successful login
  if (user.loginAttempts > 0) {
    await user.resetLoginAttempts();
  }
  
  // Update last login
  user.lastLogin = new Date();
  await user.save();
  
  return user;
};

// Static method to check subscription limits
userSchema.statics.checkSubscriptionLimits = function(user, resourceType) {
  const limits = user.limits;
  const usage = user.usage;
  
  switch (resourceType) {
    case 'targets':
      return usage.currentTargets < limits.maxTargets;
    case 'scans':
      return usage.scansThisMonth < limits.maxScansPerMonth;
    case 'reports':
      return usage.currentReports < limits.maxReports;
    default:
      return false;
  }
};

module.exports = mongoose.model('User', userSchema);