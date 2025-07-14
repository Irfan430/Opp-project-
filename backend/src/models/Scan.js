const mongoose = require('mongoose');

/**
 * Scan Schema for storing vulnerability scan results
 * Supports multiple scan types and comprehensive vulnerability tracking
 */
const scanSchema = new mongoose.Schema({
  // Basic Information
  name: {
    type: String,
    required: [true, 'Scan name is required'],
    trim: true,
    maxlength: [100, 'Scan name cannot exceed 100 characters']
  },
  description: {
    type: String,
    trim: true,
    maxlength: [500, 'Description cannot exceed 500 characters']
  },

  // Scan Configuration
  target: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Target',
    required: true
  },
  scanType: {
    type: String,
    enum: [
      'port_scan', 'vulnerability_scan', 'web_scan', 'ssl_scan', 
      'dns_scan', 'brute_force', 'compliance_scan', 'network_scan'
    ],
    required: [true, 'Scan type is required']
  },
  scanProfile: {
    type: String,
    enum: ['quick', 'standard', 'comprehensive', 'custom'],
    default: 'standard'
  },

  // Scan Status
  status: {
    type: String,
    enum: ['pending', 'queued', 'running', 'completed', 'failed', 'cancelled', 'timeout'],
    default: 'pending'
  },
  progress: {
    type: Number,
    min: 0,
    max: 100,
    default: 0
  },

  // Timing Information
  scheduledTime: Date,
  startTime: Date,
  endTime: Date,
  duration: {
    type: Number, // in milliseconds
    default: 0
  },
  timeout: {
    type: Number,
    default: 300000 // 5 minutes
  },

  // Owner and Permissions
  owner: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  organization: String,
  triggeredBy: {
    type: String,
    enum: ['manual', 'scheduled', 'api', 'webhook', 'ci_cd'],
    default: 'manual'
  },

  // Scan Configuration Details
  configuration: {
    ports: {
      range: String, // e.g., "1-1000", "80,443,8080"
      top_ports: Number,
      custom_ports: [Number]
    },
    threads: {
      type: Number,
      default: 10,
      min: 1,
      max: 100
    },
    intensity: {
      type: Number,
      default: 4,
      min: 0,
      max: 5
    },
    scripts: [String],
    options: mongoose.Schema.Types.Mixed,
    userAgent: String,
    cookies: String,
    headers: mongoose.Schema.Types.Mixed
  },

  // Results Summary
  summary: {
    totalVulnerabilities: {
      type: Number,
      default: 0
    },
    severityCount: {
      critical: { type: Number, default: 0 },
      high: { type: Number, default: 0 },
      medium: { type: Number, default: 0 },
      low: { type: Number, default: 0 },
      info: { type: Number, default: 0 }
    },
    riskScore: {
      type: Number,
      min: 0,
      max: 100,
      default: 0
    },
    complianceScore: {
      type: Number,
      min: 0,
      max: 100,
      default: 0
    }
  },

  // Detailed Results
  vulnerabilities: [{
    id: String,
    name: {
      type: String,
      required: true
    },
    description: String,
    severity: {
      type: String,
      enum: ['critical', 'high', 'medium', 'low', 'info'],
      required: true
    },
    cvss: {
      version: String,
      baseScore: Number,
      vectorString: String,
      exploitabilityScore: Number,
      impactScore: Number
    },
    cve: [String],
    cwe: [String],
    references: [String],
    solution: String,
    evidence: String,
    location: {
      host: String,
      port: Number,
      protocol: String,
      service: String,
      path: String,
      parameter: String
    },
    plugin: {
      id: String,
      name: String,
      family: String
    },
    firstSeen: {
      type: Date,
      default: Date.now
    },
    status: {
      type: String,
      enum: ['new', 'existing', 'fixed', 'false_positive', 'accepted_risk'],
      default: 'new'
    },
    tags: [String]
  }],

  // Host Discovery Results
  hosts: [{
    ip: String,
    hostname: String,
    status: {
      type: String,
      enum: ['up', 'down', 'filtered']
    },
    ports: [{
      port: Number,
      protocol: String,
      state: String,
      service: String,
      version: String,
      banner: String
    }],
    os: {
      name: String,
      version: String,
      accuracy: Number
    },
    responseTime: Number
  }],

  // Web Application Scan Results
  webFindings: [{
    type: {
      type: String,
      enum: [
        'xss', 'sql_injection', 'csrf', 'lfi', 'rfi', 'directory_traversal',
        'command_injection', 'xxe', 'ssrf', 'insecure_deserialization',
        'broken_authentication', 'sensitive_data_exposure'
      ]
    },
    url: String,
    method: String,
    parameter: String,
    payload: String,
    response: String,
    evidence: String
  }],

  // SSL/TLS Scan Results
  sslFindings: [{
    issue: String,
    severity: String,
    description: String,
    certificate: {
      subject: String,
      issuer: String,
      serialNumber: String,
      notBefore: Date,
      notAfter: Date,
      fingerprint: String,
      keySize: Number,
      signatureAlgorithm: String
    },
    protocols: [String],
    ciphers: [String],
    vulnerabilities: [String]
  }],

  // Brute Force Results
  bruteForceResults: [{
    service: String,
    host: String,
    port: Number,
    protocol: String,
    successfulCredentials: [{
      username: String,
      password: String,
      accessLevel: String
    }],
    attemptsMade: Number,
    timeToBreak: Number, // in seconds
    methodology: String
  }],

  // Compliance Results
  complianceResults: [{
    standard: String,
    requirements: [{
      id: String,
      title: String,
      status: {
        type: String,
        enum: ['pass', 'fail', 'not_applicable', 'manual_review']
      },
      score: Number,
      evidence: String,
      remediation: String
    }]
  }],

  // Raw Output
  rawOutput: {
    nmap: String,
    nikto: String,
    custom: mongoose.Schema.Types.Mixed
  },

  // Files and Attachments
  files: [{
    filename: String,
    path: String,
    size: Number,
    type: String,
    description: String
  }],

  // Error Information
  errors: [{
    timestamp: {
      type: Date,
      default: Date.now
    },
    level: {
      type: String,
      enum: ['error', 'warning', 'info']
    },
    message: String,
    component: String,
    details: mongoose.Schema.Types.Mixed
  }],

  // AI/ML Predictions
  predictions: {
    futureRiskScore: Number,
    attackProbability: Number,
    timeToCompromise: Number, // in days
    predictedVulnerabilities: [{
      type: String,
      probability: Number,
      timeframe: String
    }],
    modelVersion: String,
    confidence: Number,
    generatedAt: Date
  },

  // Comparison with Previous Scans
  comparison: {
    previousScanId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Scan'
    },
    newVulnerabilities: Number,
    fixedVulnerabilities: Number,
    riskScoreChange: Number,
    summary: String
  },

  // Notifications
  notifications: {
    sent: [{
      channel: {
        type: String,
        enum: ['email', 'slack', 'telegram', 'webhook']
      },
      timestamp: {
        type: Date,
        default: Date.now
      },
      status: {
        type: String,
        enum: ['sent', 'failed', 'pending']
      },
      recipient: String,
      message: String
    }],
    alertLevel: {
      type: String,
      enum: ['none', 'low', 'medium', 'high', 'critical']
    }
  },

  // Quality Assurance
  quality: {
    falsePositiveRate: Number,
    coverage: Number,
    completeness: Number,
    accuracy: Number,
    reviewStatus: {
      type: String,
      enum: ['pending', 'reviewed', 'approved', 'rejected']
    },
    reviewedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    reviewNotes: String
  },

  // Integration Data
  integration: {
    cicdPipeline: String,
    buildNumber: String,
    commitHash: String,
    branch: String,
    repository: String,
    environment: String
  },

  // Metadata
  tags: [String],
  notes: String,
  customFields: mongoose.Schema.Types.Mixed,
  
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
scanSchema.index({ target: 1 });
scanSchema.index({ owner: 1 });
scanSchema.index({ status: 1 });
scanSchema.index({ scanType: 1 });
scanSchema.index({ startTime: 1 });
scanSchema.index({ 'summary.riskScore': -1 });
scanSchema.index({ 'summary.severityCount.critical': -1 });
scanSchema.index({ organization: 1 });
scanSchema.index({ triggeredBy: 1 });

// Compound indexes
scanSchema.index({ target: 1, startTime: -1 });
scanSchema.index({ owner: 1, status: 1 });
scanSchema.index({ scanType: 1, status: 1 });
scanSchema.index({ 'summary.riskScore': -1, status: 1 });

// Virtual for scan duration in human-readable format
scanSchema.virtual('durationFormatted').get(function() {
  if (!this.duration) return '0s';
  
  const seconds = Math.floor(this.duration / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  
  if (hours > 0) {
    return `${hours}h ${minutes % 60}m ${seconds % 60}s`;
  } else if (minutes > 0) {
    return `${minutes}m ${seconds % 60}s`;
  } else {
    return `${seconds}s`;
  }
});

// Virtual for risk level based on score
scanSchema.virtual('riskLevel').get(function() {
  const score = this.summary.riskScore;
  if (score >= 80) return 'critical';
  if (score >= 60) return 'high';
  if (score >= 40) return 'medium';
  if (score >= 20) return 'low';
  return 'info';
});

// Pre-save middleware to calculate summary statistics
scanSchema.pre('save', function(next) {
  if (this.isModified('vulnerabilities')) {
    // Calculate vulnerability counts
    const counts = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0
    };
    
    this.vulnerabilities.forEach(vuln => {
      counts[vuln.severity]++;
    });
    
    this.summary.severityCount = counts;
    this.summary.totalVulnerabilities = this.vulnerabilities.length;
    
    // Calculate risk score
    const riskScore = (
      counts.critical * 10 +
      counts.high * 7 +
      counts.medium * 4 +
      counts.low * 2 +
      counts.info * 1
    );
    
    this.summary.riskScore = Math.min(riskScore, 100);
  }
  
  // Calculate duration if end time is set
  if (this.startTime && this.endTime) {
    this.duration = this.endTime.getTime() - this.startTime.getTime();
  }
  
  next();
});

// Instance method to add vulnerability
scanSchema.methods.addVulnerability = function(vulnerability) {
  this.vulnerabilities.push(vulnerability);
  return this.save();
};

// Instance method to update progress
scanSchema.methods.updateProgress = function(progress, status) {
  this.progress = progress;
  if (status) this.status = status;
  return this.save();
};

// Instance method to complete scan
scanSchema.methods.completeScan = function(status = 'completed') {
  this.status = status;
  this.endTime = new Date();
  this.progress = 100;
  return this.save();
};

// Instance method to compare with previous scan
scanSchema.methods.compareWithPrevious = async function() {
  const previousScan = await this.constructor.findOne({
    target: this.target,
    status: 'completed',
    _id: { $ne: this._id },
    startTime: { $lt: this.startTime }
  }).sort({ startTime: -1 });
  
  if (!previousScan) return null;
  
  const currentVulns = new Set(this.vulnerabilities.map(v => v.id || v.name));
  const previousVulns = new Set(previousScan.vulnerabilities.map(v => v.id || v.name));
  
  const newVulns = [...currentVulns].filter(v => !previousVulns.has(v));
  const fixedVulns = [...previousVulns].filter(v => !currentVulns.has(v));
  
  this.comparison = {
    previousScanId: previousScan._id,
    newVulnerabilities: newVulns.length,
    fixedVulnerabilities: fixedVulns.length,
    riskScoreChange: this.summary.riskScore - previousScan.summary.riskScore,
    summary: `${newVulns.length} new, ${fixedVulns.length} fixed vulnerabilities`
  };
  
  return this.save();
};

// Static method to find recent scans
scanSchema.statics.findRecent = function(userId, limit = 10) {
  return this.find({ owner: userId })
    .sort({ startTime: -1 })
    .limit(limit)
    .populate('target', 'name type value');
};

// Static method to find scans by risk level
scanSchema.statics.findByRiskLevel = function(riskLevel, userId) {
  const scoreRanges = {
    critical: { $gte: 80 },
    high: { $gte: 60, $lt: 80 },
    medium: { $gte: 40, $lt: 60 },
    low: { $gte: 20, $lt: 40 },
    info: { $lt: 20 }
  };
  
  return this.find({
    owner: userId,
    'summary.riskScore': scoreRanges[riskLevel],
    status: 'completed'
  }).sort({ 'summary.riskScore': -1 });
};

// Static method to get vulnerability trends
scanSchema.statics.getVulnerabilityTrends = async function(userId, days = 30) {
  const startDate = new Date();
  startDate.setDate(startDate.getDate() - days);
  
  return this.aggregate([
    {
      $match: {
        owner: new mongoose.Types.ObjectId(userId),
        status: 'completed',
        startTime: { $gte: startDate }
      }
    },
    {
      $group: {
        _id: {
          $dateToString: { format: '%Y-%m-%d', date: '$startTime' }
        },
        totalScans: { $sum: 1 },
        totalVulnerabilities: { $sum: '$summary.totalVulnerabilities' },
        averageRiskScore: { $avg: '$summary.riskScore' },
        criticalVulns: { $sum: '$summary.severityCount.critical' },
        highVulns: { $sum: '$summary.severityCount.high' }
      }
    },
    { $sort: { '_id': 1 } }
  ]);
};

module.exports = mongoose.model('Scan', scanSchema);