const mongoose = require('mongoose');

/**
 * Report Schema for generating and managing security reports
 * Supports various report types and formats
 */
const reportSchema = new mongoose.Schema({
  // Basic Information
  title: {
    type: String,
    required: [true, 'Report title is required'],
    trim: true,
    maxlength: [200, 'Title cannot exceed 200 characters']
  },
  description: {
    type: String,
    trim: true,
    maxlength: [1000, 'Description cannot exceed 1000 characters']
  },

  // Report Configuration
  type: {
    type: String,
    enum: [
      'vulnerability_summary', 'executive_summary', 'technical_details',
      'compliance_report', 'trend_analysis', 'custom', 'comparative_analysis',
      'risk_assessment', 'penetration_test'
    ],
    required: [true, 'Report type is required']
  },
  template: {
    type: String,
    enum: ['standard', 'executive', 'technical', 'compliance', 'custom'],
    default: 'standard'
  },
  format: {
    type: String,
    enum: ['pdf', 'html', 'json', 'csv', 'xlsx'],
    default: 'pdf'
  },

  // Scope and Filters
  scope: {
    targets: [{
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Target'
    }],
    scans: [{
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Scan'
    }],
    dateRange: {
      start: Date,
      end: Date
    },
    severityLevels: [{
      type: String,
      enum: ['critical', 'high', 'medium', 'low', 'info']
    }],
    scanTypes: [{
      type: String,
      enum: ['port_scan', 'vulnerability_scan', 'web_scan', 'ssl_scan', 'dns_scan', 'brute_force']
    }],
    tags: [String],
    includeResolved: {
      type: Boolean,
      default: false
    }
  },

  // Owner and Permissions
  owner: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  organization: String,
  visibility: {
    type: String,
    enum: ['private', 'organization', 'public'],
    default: 'private'
  },
  sharedWith: [{
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    permission: {
      type: String,
      enum: ['read', 'write'],
      default: 'read'
    },
    sharedAt: {
      type: Date,
      default: Date.now
    }
  }],

  // Generation Status
  status: {
    type: String,
    enum: ['pending', 'generating', 'completed', 'failed', 'expired'],
    default: 'pending'
  },
  progress: {
    type: Number,
    min: 0,
    max: 100,
    default: 0
  },
  
  // File Information
  file: {
    filename: String,
    path: String,
    size: Number,
    mimeType: String,
    downloadCount: {
      type: Number,
      default: 0
    },
    expiresAt: Date
  },

  // Report Content Structure
  content: {
    executiveSummary: {
      overview: String,
      keyFindings: [String],
      recommendations: [String],
      riskLevel: {
        type: String,
        enum: ['critical', 'high', 'medium', 'low']
      }
    },
    
    methodology: {
      scanTypes: [String],
      tools: [String],
      timeframe: String,
      scope: String,
      limitations: [String]
    },

    findings: {
      totalVulnerabilities: Number,
      severityBreakdown: {
        critical: Number,
        high: Number,
        medium: Number,
        low: Number,
        info: Number
      },
      topVulnerabilities: [{
        name: String,
        severity: String,
        count: Number,
        description: String,
        impact: String,
        recommendation: String
      }],
      affectedAssets: [{
        target: String,
        vulnerabilityCount: Number,
        riskScore: Number
      }]
    },

    riskAnalysis: {
      overallRiskScore: Number,
      riskFactors: [String],
      businessImpact: String,
      likelihood: String,
      threatActors: [String]
    },

    compliance: [{
      standard: String,
      overallScore: Number,
      requirements: [{
        id: String,
        title: String,
        status: String,
        gap: String
      }]
    }],

    trends: {
      vulnerabilityTrends: [{
        date: String,
        count: Number,
        severity: String
      }],
      riskTrends: [{
        date: String,
        score: Number
      }],
      comparisonWithPrevious: {
        newVulnerabilities: Number,
        fixedVulnerabilities: Number,
        riskChange: Number
      }
    },

    recommendations: [{
      priority: {
        type: String,
        enum: ['high', 'medium', 'low']
      },
      category: String,
      title: String,
      description: String,
      effort: String,
      impact: String,
      timeline: String
    }],

    appendices: {
      vulnerabilityDetails: Boolean,
      scanResults: Boolean,
      technicalData: Boolean,
      references: [String]
    }
  },

  // Customization Options
  customization: {
    branding: {
      logo: String,
      colors: {
        primary: String,
        secondary: String,
        accent: String
      },
      companyName: String,
      footer: String
    },
    
    sections: [{
      name: String,
      enabled: {
        type: Boolean,
        default: true
      },
      order: Number,
      customContent: String
    }],

    charts: [{
      type: String,
      title: String,
      data: mongoose.Schema.Types.Mixed,
      enabled: {
        type: Boolean,
        default: true
      }
    }]
  },

  // Generation Metadata
  generation: {
    startTime: Date,
    endTime: Date,
    duration: Number, // in milliseconds
    generatedBy: {
      type: String,
      enum: ['user', 'scheduled', 'api'],
      default: 'user'
    },
    version: {
      type: String,
      default: '1.0'
    },
    engine: {
      type: String,
      default: 'puppeteer'
    },
    template_version: String,
    dataVersion: Date
  },

  // Analytics and Tracking
  analytics: {
    views: {
      type: Number,
      default: 0
    },
    downloads: {
      type: Number,
      default: 0
    },
    shares: {
      type: Number,
      default: 0
    },
    lastAccessed: Date,
    accessHistory: [{
      user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
      },
      action: {
        type: String,
        enum: ['view', 'download', 'share']
      },
      timestamp: {
        type: Date,
        default: Date.now
      },
      ipAddress: String
    }]
  },

  // Scheduling
  schedule: {
    isRecurring: {
      type: Boolean,
      default: false
    },
    frequency: {
      type: String,
      enum: ['daily', 'weekly', 'monthly', 'quarterly'],
      required: function() { return this.schedule.isRecurring; }
    },
    nextGeneration: Date,
    lastGeneration: Date,
    autoEmail: {
      type: Boolean,
      default: false
    },
    recipients: [String]
  },

  // Quality and Validation
  quality: {
    reviewRequired: {
      type: Boolean,
      default: false
    },
    reviewedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    reviewNotes: String,
    approvalStatus: {
      type: String,
      enum: ['pending', 'approved', 'rejected'],
      default: 'approved'
    },
    qualityScore: Number,
    completeness: Number
  },

  // Error Handling
  errors: [{
    timestamp: {
      type: Date,
      default: Date.now
    },
    message: String,
    stack: String,
    context: mongoose.Schema.Types.Mixed
  }],

  // Metadata
  tags: [String],
  notes: String,
  
  // Audit Trail
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  lastModifiedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }
}, {
  timestamps: true
});

// Indexes for performance
reportSchema.index({ owner: 1 });
reportSchema.index({ type: 1 });
reportSchema.index({ status: 1 });
reportSchema.index({ organization: 1 });
reportSchema.index({ 'schedule.nextGeneration': 1 });
reportSchema.index({ createdAt: -1 });
reportSchema.index({ 'file.expiresAt': 1 });

// Compound indexes
reportSchema.index({ owner: 1, status: 1 });
reportSchema.index({ type: 1, owner: 1 });
reportSchema.index({ organization: 1, createdAt: -1 });

// Virtual for file size in human-readable format
reportSchema.virtual('fileSizeFormatted').get(function() {
  if (!this.file || !this.file.size) return '0 B';
  
  const bytes = this.file.size;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  
  return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${sizes[i]}`;
});

// Virtual for generation duration in human-readable format
reportSchema.virtual('generationDurationFormatted').get(function() {
  if (!this.generation || !this.generation.duration) return '0s';
  
  const seconds = Math.floor(this.generation.duration / 1000);
  const minutes = Math.floor(seconds / 60);
  
  if (minutes > 0) {
    return `${minutes}m ${seconds % 60}s`;
  } else {
    return `${seconds}s`;
  }
});

// Virtual to check if report is expired
reportSchema.virtual('isExpired').get(function() {
  if (!this.file || !this.file.expiresAt) return false;
  return new Date() > this.file.expiresAt;
});

// Pre-save middleware to set expiration date
reportSchema.pre('save', function(next) {
  if (this.isNew && !this.file.expiresAt) {
    // Set expiration to 30 days from creation
    this.file.expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
  }
  next();
});

// Instance method to record access
reportSchema.methods.recordAccess = function(userId, action, ipAddress) {
  this.analytics.accessHistory.push({
    user: userId,
    action: action,
    ipAddress: ipAddress
  });
  
  switch (action) {
    case 'view':
      this.analytics.views += 1;
      break;
    case 'download':
      this.analytics.downloads += 1;
      this.file.downloadCount += 1;
      break;
    case 'share':
      this.analytics.shares += 1;
      break;
  }
  
  this.analytics.lastAccessed = new Date();
  return this.save();
};

// Instance method to update generation progress
reportSchema.methods.updateProgress = function(progress, status) {
  this.progress = progress;
  if (status) this.status = status;
  return this.save();
};

// Instance method to complete generation
reportSchema.methods.completeGeneration = function(fileInfo) {
  this.status = 'completed';
  this.progress = 100;
  this.generation.endTime = new Date();
  this.generation.duration = this.generation.endTime - this.generation.startTime;
  
  if (fileInfo) {
    this.file = { ...this.file, ...fileInfo };
  }
  
  return this.save();
};

// Instance method to check if user has access
reportSchema.methods.hasAccess = function(userId, permission = 'read') {
  // Owner always has access
  if (this.owner.toString() === userId.toString()) {
    return true;
  }
  
  // Check shared access
  const sharedAccess = this.sharedWith.find(share => 
    share.user.toString() === userId.toString()
  );
  
  if (sharedAccess) {
    if (permission === 'read') return true;
    if (permission === 'write') return sharedAccess.permission === 'write';
  }
  
  return false;
};

// Static method to find reports due for generation
reportSchema.statics.findDueForGeneration = function() {
  return this.find({
    'schedule.isRecurring': true,
    'schedule.nextGeneration': { $lte: new Date() },
    status: { $ne: 'generating' }
  });
};

// Static method to find expired reports
reportSchema.statics.findExpired = function() {
  return this.find({
    'file.expiresAt': { $lte: new Date() },
    status: 'completed'
  });
};

// Static method to get report statistics
reportSchema.statics.getStatistics = async function(userId, days = 30) {
  const startDate = new Date();
  startDate.setDate(startDate.getDate() - days);
  
  return this.aggregate([
    {
      $match: {
        owner: new mongoose.Types.ObjectId(userId),
        createdAt: { $gte: startDate }
      }
    },
    {
      $group: {
        _id: null,
        totalReports: { $sum: 1 },
        completedReports: {
          $sum: { $cond: [{ $eq: ['$status', 'completed'] }, 1, 0] }
        },
        totalDownloads: { $sum: '$analytics.downloads' },
        totalViews: { $sum: '$analytics.views' },
        averageGenerationTime: { $avg: '$generation.duration' },
        reportsByType: {
          $push: {
            type: '$type',
            count: 1
          }
        }
      }
    }
  ]);
};

module.exports = mongoose.model('Report', reportSchema);