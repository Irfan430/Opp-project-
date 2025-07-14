const mongoose = require('mongoose');

/**
 * PhishingCampaign Schema for managing phishing simulation training
 * Supports email campaigns, user tracking, and educational content
 */
const phishingCampaignSchema = new mongoose.Schema({
  // Basic Information
  name: {
    type: String,
    required: [true, 'Campaign name is required'],
    trim: true,
    maxlength: [100, 'Campaign name cannot exceed 100 characters']
  },
  description: {
    type: String,
    trim: true,
    maxlength: [500, 'Description cannot exceed 500 characters']
  },

  // Campaign Configuration
  type: {
    type: String,
    enum: ['training', 'assessment', 'awareness', 'test'],
    default: 'training'
  },
  difficulty: {
    type: String,
    enum: ['beginner', 'intermediate', 'advanced', 'expert'],
    default: 'beginner'
  },
  category: {
    type: String,
    enum: [
      'credential_harvesting', 'malware_delivery', 'business_email_compromise',
      'social_engineering', 'spear_phishing', 'whaling', 'smishing', 'vishing'
    ],
    required: [true, 'Campaign category is required']
  },

  // Owner and Organization
  owner: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  organization: String,

  // Campaign Status
  status: {
    type: String,
    enum: ['draft', 'scheduled', 'active', 'paused', 'completed', 'cancelled'],
    default: 'draft'
  },
  progress: {
    type: Number,
    min: 0,
    max: 100,
    default: 0
  },

  // Scheduling
  schedule: {
    startDate: {
      type: Date,
      required: [true, 'Start date is required']
    },
    endDate: Date,
    timezone: {
      type: String,
      default: 'UTC'
    },
    sendPattern: {
      type: String,
      enum: ['immediate', 'staggered', 'random'],
      default: 'staggered'
    },
    staggerDelay: {
      type: Number, // in minutes
      default: 15
    }
  },

  // Email Template
  emailTemplate: {
    subject: {
      type: String,
      required: [true, 'Email subject is required'],
      maxlength: [200, 'Subject cannot exceed 200 characters']
    },
    senderName: {
      type: String,
      required: [true, 'Sender name is required']
    },
    senderEmail: {
      type: String,
      required: [true, 'Sender email is required']
    },
    htmlContent: {
      type: String,
      required: [true, 'Email content is required']
    },
    textContent: String,
    attachments: [{
      filename: String,
      path: String,
      contentType: String,
      description: String
    }],
    landingPageUrl: String,
    trackingPixel: {
      type: Boolean,
      default: true
    }
  },

  // Landing Page Configuration
  landingPage: {
    type: {
      type: String,
      enum: ['credential_harvest', 'educational', 'malware_warning', 'custom'],
      default: 'credential_harvest'
    },
    title: String,
    content: String,
    customHtml: String,
    captureCredentials: {
      type: Boolean,
      default: false
    },
    redirectUrl: String,
    educationalContent: {
      enabled: {
        type: Boolean,
        default: true
      },
      title: String,
      message: String,
      tips: [String],
      resources: [String]
    }
  },

  // Target Recipients
  recipients: [{
    email: {
      type: String,
      required: true
    },
    firstName: String,
    lastName: String,
    department: String,
    position: String,
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    
    // Tracking Information
    emailSent: {
      type: Boolean,
      default: false
    },
    emailSentAt: Date,
    emailOpened: {
      type: Boolean,
      default: false
    },
    emailOpenedAt: Date,
    linkClicked: {
      type: Boolean,
      default: false
    },
    linkClickedAt: Date,
    credentialsEntered: {
      type: Boolean,
      default: false
    },
    credentialsEnteredAt: Date,
    reported: {
      type: Boolean,
      default: false
    },
    reportedAt: Date,
    
    // Captured Data
    capturedCredentials: {
      username: String,
      password: String, // This should be hashed/encrypted
      additionalFields: mongoose.Schema.Types.Mixed
    },
    ipAddress: String,
    userAgent: String,
    
    // Training Completion
    trainingCompleted: {
      type: Boolean,
      default: false
    },
    trainingCompletedAt: Date,
    trainingScore: Number,
    
    // Status
    status: {
      type: String,
      enum: ['pending', 'sent', 'opened', 'clicked', 'compromised', 'reported', 'trained'],
      default: 'pending'
    }
  }],

  // Campaign Results Summary
  results: {
    totalRecipients: {
      type: Number,
      default: 0
    },
    emailsSent: {
      type: Number,
      default: 0
    },
    emailsOpened: {
      type: Number,
      default: 0
    },
    linksClicked: {
      type: Number,
      default: 0
    },
    credentialsSubmitted: {
      type: Number,
      default: 0
    },
    reportsReceived: {
      type: Number,
      default: 0
    },
    trainingCompleted: {
      type: Number,
      default: 0
    },
    
    // Rates (calculated)
    openRate: {
      type: Number,
      default: 0
    },
    clickRate: {
      type: Number,
      default: 0
    },
    compromiseRate: {
      type: Number,
      default: 0
    },
    reportingRate: {
      type: Number,
      default: 0
    },
    trainingCompletionRate: {
      type: Number,
      default: 0
    }
  },

  // Analytics and Insights
  analytics: {
    byDepartment: [{
      department: String,
      total: Number,
      compromised: Number,
      reported: Number,
      trained: Number
    }],
    byTimeOfDay: [{
      hour: Number,
      opens: Number,
      clicks: Number,
      compromises: Number
    }],
    deviceTypes: [{
      type: String,
      count: Number
    }],
    browsers: [{
      name: String,
      count: Number
    }],
    operatingSystems: [{
      name: String,
      count: Number
    }]
  },

  // Educational Content
  education: {
    enabled: {
      type: Boolean,
      default: true
    },
    modules: [{
      title: String,
      content: String,
      type: {
        type: String,
        enum: ['video', 'article', 'quiz', 'interactive']
      },
      duration: Number, // in minutes
      mandatory: {
        type: Boolean,
        default: true
      }
    }],
    quiz: {
      enabled: {
        type: Boolean,
        default: false
      },
      passingScore: {
        type: Number,
        default: 80
      },
      questions: [{
        question: String,
        options: [String],
        correctAnswer: Number,
        explanation: String
      }]
    }
  },

  // Compliance and Reporting
  compliance: {
    gdprCompliant: {
      type: Boolean,
      default: true
    },
    consentObtained: {
      type: Boolean,
      default: false
    },
    dataRetentionPeriod: {
      type: Number, // in days
      default: 365
    },
    anonymizeResults: {
      type: Boolean,
      default: false
    }
  },

  // Notifications and Alerts
  notifications: {
    enabled: {
      type: Boolean,
      default: true
    },
    realTimeAlerts: {
      type: Boolean,
      default: false
    },
    reportingThreshold: {
      type: Number, // percentage of users who clicked
      default: 10
    },
    recipients: [String],
    channels: [{
      type: String,
      enum: ['email', 'slack', 'telegram']
    }]
  },

  // Security and Safety
  security: {
    safetyChecks: {
      type: Boolean,
      default: true
    },
    maxClicksPerUser: {
      type: Number,
      default: 1
    },
    blockMaliciousIPs: {
      type: Boolean,
      default: true
    },
    honeypotDetection: {
      type: Boolean,
      default: true
    }
  },

  // Integration
  integration: {
    lmsIntegration: {
      enabled: {
        type: Boolean,
        default: false
      },
      platform: String,
      courseId: String
    },
    hrIntegration: {
      enabled: {
        type: Boolean,
        default: false
      },
      platform: String,
      trackPerformance: {
        type: Boolean,
        default: false
      }
    }
  },

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
phishingCampaignSchema.index({ owner: 1 });
phishingCampaignSchema.index({ status: 1 });
phishingCampaignSchema.index({ organization: 1 });
phishingCampaignSchema.index({ category: 1 });
phishingCampaignSchema.index({ 'schedule.startDate': 1 });
phishingCampaignSchema.index({ 'recipients.email': 1 });

// Compound indexes
phishingCampaignSchema.index({ owner: 1, status: 1 });
phishingCampaignSchema.index({ organization: 1, status: 1 });

// Virtual for campaign duration
phishingCampaignSchema.virtual('duration').get(function() {
  if (!this.schedule.startDate || !this.schedule.endDate) return null;
  return Math.ceil((this.schedule.endDate - this.schedule.startDate) / (1000 * 60 * 60 * 24));
});

// Virtual for overall success rate
phishingCampaignSchema.virtual('successRate').get(function() {
  if (this.results.totalRecipients === 0) return 0;
  const successfulUsers = this.results.reportsReceived + this.results.trainingCompleted;
  return Math.round((successfulUsers / this.results.totalRecipients) * 100);
});

// Pre-save middleware to calculate results
phishingCampaignSchema.pre('save', function(next) {
  if (this.isModified('recipients')) {
    const results = {
      totalRecipients: this.recipients.length,
      emailsSent: this.recipients.filter(r => r.emailSent).length,
      emailsOpened: this.recipients.filter(r => r.emailOpened).length,
      linksClicked: this.recipients.filter(r => r.linkClicked).length,
      credentialsSubmitted: this.recipients.filter(r => r.credentialsEntered).length,
      reportsReceived: this.recipients.filter(r => r.reported).length,
      trainingCompleted: this.recipients.filter(r => r.trainingCompleted).length
    };

    // Calculate rates
    if (results.emailsSent > 0) {
      results.openRate = Math.round((results.emailsOpened / results.emailsSent) * 100);
      results.clickRate = Math.round((results.linksClicked / results.emailsSent) * 100);
      results.compromiseRate = Math.round((results.credentialsSubmitted / results.emailsSent) * 100);
      results.reportingRate = Math.round((results.reportsReceived / results.emailsSent) * 100);
      results.trainingCompletionRate = Math.round((results.trainingCompleted / results.emailsSent) * 100);
    }

    this.results = results;

    // Update progress
    if (results.totalRecipients > 0) {
      const completedActions = results.reportsReceived + results.trainingCompleted;
      this.progress = Math.round((completedActions / results.totalRecipients) * 100);
    }
  }
  next();
});

// Instance method to add recipient
phishingCampaignSchema.methods.addRecipient = function(recipientData) {
  this.recipients.push(recipientData);
  return this.save();
};

// Instance method to update recipient status
phishingCampaignSchema.methods.updateRecipientStatus = function(email, updateData) {
  const recipient = this.recipients.find(r => r.email === email);
  if (recipient) {
    Object.assign(recipient, updateData);
    return this.save();
  }
  return Promise.reject(new Error('Recipient not found'));
};

// Instance method to record interaction
phishingCampaignSchema.methods.recordInteraction = function(email, interactionType, data = {}) {
  const recipient = this.recipients.find(r => r.email === email);
  if (!recipient) {
    throw new Error('Recipient not found');
  }

  const timestamp = new Date();
  
  switch (interactionType) {
    case 'email_sent':
      recipient.emailSent = true;
      recipient.emailSentAt = timestamp;
      recipient.status = 'sent';
      break;
    case 'email_opened':
      recipient.emailOpened = true;
      recipient.emailOpenedAt = timestamp;
      recipient.status = 'opened';
      break;
    case 'link_clicked':
      recipient.linkClicked = true;
      recipient.linkClickedAt = timestamp;
      recipient.status = 'clicked';
      break;
    case 'credentials_entered':
      recipient.credentialsEntered = true;
      recipient.credentialsEnteredAt = timestamp;
      recipient.capturedCredentials = data.credentials;
      recipient.status = 'compromised';
      break;
    case 'reported':
      recipient.reported = true;
      recipient.reportedAt = timestamp;
      recipient.status = 'reported';
      break;
    case 'training_completed':
      recipient.trainingCompleted = true;
      recipient.trainingCompletedAt = timestamp;
      recipient.trainingScore = data.score;
      recipient.status = 'trained';
      break;
  }

  if (data.ipAddress) recipient.ipAddress = data.ipAddress;
  if (data.userAgent) recipient.userAgent = data.userAgent;

  return this.save();
};

// Instance method to start campaign
phishingCampaignSchema.methods.startCampaign = function() {
  this.status = 'active';
  this.schedule.startDate = new Date();
  return this.save();
};

// Instance method to complete campaign
phishingCampaignSchema.methods.completeCampaign = function() {
  this.status = 'completed';
  this.schedule.endDate = new Date();
  this.progress = 100;
  return this.save();
};

// Static method to find active campaigns
phishingCampaignSchema.statics.findActive = function() {
  return this.find({
    status: 'active',
    'schedule.startDate': { $lte: new Date() },
    $or: [
      { 'schedule.endDate': { $exists: false } },
      { 'schedule.endDate': { $gte: new Date() } }
    ]
  });
};

// Static method to get campaign statistics
phishingCampaignSchema.statics.getStatistics = async function(userId, days = 30) {
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
        totalCampaigns: { $sum: 1 },
        activeCampaigns: {
          $sum: { $cond: [{ $eq: ['$status', 'active'] }, 1, 0] }
        },
        completedCampaigns: {
          $sum: { $cond: [{ $eq: ['$status', 'completed'] }, 1, 0] }
        },
        totalRecipients: { $sum: '$results.totalRecipients' },
        totalCompromised: { $sum: '$results.credentialsSubmitted' },
        totalReported: { $sum: '$results.reportsReceived' },
        averageClickRate: { $avg: '$results.clickRate' },
        averageCompromiseRate: { $avg: '$results.compromiseRate' }
      }
    }
  ]);
};

module.exports = mongoose.model('PhishingCampaign', phishingCampaignSchema);