const mongoose = require('mongoose');

/**
 * Target Schema for storing scan targets
 * Supports domains, IP addresses, and specific services
 */
const targetSchema = new mongoose.Schema({
  // Basic Information
  name: {
    type: String,
    required: [true, 'Target name is required'],
    trim: true,
    maxlength: [100, 'Target name cannot exceed 100 characters']
  },
  description: {
    type: String,
    trim: true,
    maxlength: [500, 'Description cannot exceed 500 characters']
  },

  // Target Details
  type: {
    type: String,
    enum: ['domain', 'ip', 'url', 'network_range'],
    required: [true, 'Target type is required']
  },
  value: {
    type: String,
    required: [true, 'Target value is required'],
    trim: true
  },
  
  // Network Information
  ipAddress: String,
  domain: String,
  ports: [{
    port: {
      type: Number,
      min: 1,
      max: 65535
    },
    protocol: {
      type: String,
      enum: ['tcp', 'udp'],
      default: 'tcp'
    },
    service: String,
    version: String,
    state: {
      type: String,
      enum: ['open', 'closed', 'filtered'],
      default: 'unknown'
    }
  }],

  // Geographic Information
  location: {
    country: String,
    region: String,
    city: String,
    coordinates: {
      latitude: Number,
      longitude: Number
    }
  },

  // Owner Information
  owner: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  organization: String,

  // Tags and Categories
  tags: [{
    type: String,
    trim: true,
    maxlength: [30, 'Tag cannot exceed 30 characters']
  }],
  category: {
    type: String,
    enum: ['production', 'staging', 'development', 'testing', 'internal', 'external'],
    default: 'external'
  },
  environment: {
    type: String,
    enum: ['production', 'staging', 'development', 'testing'],
    default: 'production'
  },
  criticality: {
    type: String,
    enum: ['critical', 'high', 'medium', 'low'],
    default: 'medium'
  },

  // Status and Configuration
  isActive: {
    type: Boolean,
    default: true
  },
  scanEnabled: {
    type: Boolean,
    default: true
  },
  monitoringEnabled: {
    type: Boolean,
    default: false
  },

  // Scan Configuration
  scanFrequency: {
    type: String,
    enum: ['manual', 'daily', 'weekly', 'monthly'],
    default: 'manual'
  },
  scanTypes: [{
    type: String,
    enum: ['port_scan', 'vulnerability_scan', 'web_scan', 'ssl_scan', 'dns_scan', 'brute_force']
  }],
  excludedScanTypes: [{
    type: String,
    enum: ['port_scan', 'vulnerability_scan', 'web_scan', 'ssl_scan', 'dns_scan', 'brute_force']
  }],

  // Scan History Summary
  lastScanDate: Date,
  lastScanId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Scan'
  },
  totalScans: {
    type: Number,
    default: 0
  },
  lastVulnerabilityCount: {
    critical: { type: Number, default: 0 },
    high: { type: Number, default: 0 },
    medium: { type: Number, default: 0 },
    low: { type: Number, default: 0 },
    info: { type: Number, default: 0 }
  },

  // Risk Assessment
  riskScore: {
    type: Number,
    min: 0,
    max: 100,
    default: 0
  },
  riskLevel: {
    type: String,
    enum: ['critical', 'high', 'medium', 'low', 'info'],
    default: 'low'
  },
  threatIntelligence: {
    isKnownMalicious: {
      type: Boolean,
      default: false
    },
    reputation: {
      type: String,
      enum: ['good', 'neutral', 'suspicious', 'malicious'],
      default: 'neutral'
    },
    blacklisted: {
      type: Boolean,
      default: false
    },
    sources: [String]
  },

  // Compliance and Governance
  complianceRequirements: [{
    standard: {
      type: String,
      enum: ['PCI-DSS', 'ISO-27001', 'SOC2', 'GDPR', 'HIPAA', 'NIST']
    },
    status: {
      type: String,
      enum: ['compliant', 'non_compliant', 'unknown'],
      default: 'unknown'
    }
  }],
  dataClassification: {
    type: String,
    enum: ['public', 'internal', 'confidential', 'restricted'],
    default: 'internal'
  },

  // Authentication Requirements
  requiresAuth: {
    type: Boolean,
    default: false
  },
  authMethods: [{
    type: String,
    enum: ['basic', 'ntlm', 'form', 'oauth', 'api_key', 'certificate']
  }],
  credentials: {
    username: String,
    // Note: Password should be encrypted
    passwordHash: String,
    additionalInfo: String
  },

  // Network Context
  networkSegment: String,
  vlan: String,
  subnet: String,
  firewall: String,
  loadBalancer: String,

  // Technology Stack
  technologies: [{
    name: String,
    version: String,
    type: {
      type: String,
      enum: ['os', 'web_server', 'database', 'framework', 'cms', 'application']
    }
  }],

  // SSL/TLS Information
  ssl: {
    enabled: {
      type: Boolean,
      default: false
    },
    version: String,
    cipher: String,
    certificateExpiry: Date,
    certificateIssuer: String,
    certificateSubject: String,
    vulnerabilities: [String]
  },

  // Notification Settings
  notifications: {
    enabled: {
      type: Boolean,
      default: true
    },
    channels: [{
      type: String,
      enum: ['email', 'slack', 'telegram', 'webhook']
    }],
    thresholds: {
      critical: { type: Boolean, default: true },
      high: { type: Boolean, default: true },
      medium: { type: Boolean, default: false },
      low: { type: Boolean, default: false }
    }
  },

  // Metadata
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
targetSchema.index({ owner: 1 });
targetSchema.index({ type: 1, value: 1 });
targetSchema.index({ organization: 1 });
targetSchema.index({ tags: 1 });
targetSchema.index({ category: 1 });
targetSchema.index({ criticality: 1 });
targetSchema.index({ riskLevel: 1 });
targetSchema.index({ lastScanDate: 1 });
targetSchema.index({ isActive: 1, scanEnabled: 1 });

// Compound indexes
targetSchema.index({ owner: 1, isActive: 1 });
targetSchema.index({ type: 1, owner: 1 });
targetSchema.index({ criticality: 1, riskLevel: 1 });

// Virtual for full display name
targetSchema.virtual('displayName').get(function() {
  return `${this.name} (${this.value})`;
});

// Virtual for risk calculation
targetSchema.virtual('calculatedRisk').get(function() {
  const weights = {
    critical: 10,
    high: 7,
    medium: 4,
    low: 2,
    info: 1
  };
  
  const vulns = this.lastVulnerabilityCount;
  const totalRisk = (
    vulns.critical * weights.critical +
    vulns.high * weights.high +
    vulns.medium * weights.medium +
    vulns.low * weights.low +
    vulns.info * weights.info
  );
  
  return Math.min(totalRisk, 100);
});

// Pre-save middleware to update risk level based on score
targetSchema.pre('save', function(next) {
  if (this.isModified('riskScore') || this.isModified('lastVulnerabilityCount')) {
    if (this.riskScore >= 80) {
      this.riskLevel = 'critical';
    } else if (this.riskScore >= 60) {
      this.riskLevel = 'high';
    } else if (this.riskScore >= 40) {
      this.riskLevel = 'medium';
    } else if (this.riskScore >= 20) {
      this.riskLevel = 'low';
    } else {
      this.riskLevel = 'info';
    }
  }
  next();
});

// Instance method to check if target is due for scan
targetSchema.methods.isDueForScan = function() {
  if (this.scanFrequency === 'manual' || !this.scanEnabled) {
    return false;
  }
  
  if (!this.lastScanDate) {
    return true;
  }
  
  const now = new Date();
  const lastScan = new Date(this.lastScanDate);
  const diffInDays = Math.floor((now - lastScan) / (1000 * 60 * 60 * 24));
  
  switch (this.scanFrequency) {
    case 'daily':
      return diffInDays >= 1;
    case 'weekly':
      return diffInDays >= 7;
    case 'monthly':
      return diffInDays >= 30;
    default:
      return false;
  }
};

// Instance method to update scan statistics
targetSchema.methods.updateScanStats = function(scanId, vulnerabilities) {
  this.lastScanDate = new Date();
  this.lastScanId = scanId;
  this.totalScans += 1;
  
  // Update vulnerability counts
  this.lastVulnerabilityCount = {
    critical: vulnerabilities.filter(v => v.severity === 'critical').length,
    high: vulnerabilities.filter(v => v.severity === 'high').length,
    medium: vulnerabilities.filter(v => v.severity === 'medium').length,
    low: vulnerabilities.filter(v => v.severity === 'low').length,
    info: vulnerabilities.filter(v => v.severity === 'info').length
  };
  
  // Recalculate risk score
  this.riskScore = this.calculatedRisk;
  
  return this.save();
};

// Static method to find targets by risk level
targetSchema.statics.findByRiskLevel = function(riskLevel, userId) {
  return this.find({ 
    owner: userId, 
    riskLevel: riskLevel,
    isActive: true 
  }).sort({ riskScore: -1 });
};

// Static method to find targets due for scanning
targetSchema.statics.findDueForScanning = function() {
  return this.find({
    isActive: true,
    scanEnabled: true,
    scanFrequency: { $ne: 'manual' }
  }).then(targets => {
    return targets.filter(target => target.isDueForScan());
  });
};

module.exports = mongoose.model('Target', targetSchema);