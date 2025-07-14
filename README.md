# 🔐 AI-Powered Cybersecurity Risk Simulation Platform

A comprehensive, production-ready cybersecurity platform that combines vulnerability scanning, AI-powered risk prediction, phishing simulations, and automated security assessments in a modern web-based dashboard.

## 🌟 Features

### ✅ Core Security Features
- **🎯 Vulnerability Scanning**: Custom Nmap/Nikto integration with automated discovery
- **🤖 AI/ML Risk Prediction**: Advanced machine learning models for threat assessment
- **🎣 Phishing Simulation**: Consent-based training campaigns with educational content
- **🛡️ Brute Force Testing**: Safe simulation on FTP, SSH, and HTTP services
- **📊 Real-time Dashboards**: Live threat visualization with heatmaps and charts
- **📄 PDF Report Generation**: Professional security assessment reports
- **🔔 Multi-channel Alerts**: Telegram, Slack, and email notifications

### ✅ Enterprise Features
- **👥 Multi-user Support**: Role-based access (Admin, Manager, Viewer)
- **💳 Billing Integration**: Stripe and PayPal for SaaS subscriptions
- **🔧 DevSecOps API**: CI/CD integration for automated security checks
- **📋 Compliance Assessment**: PCI-DSS, ISO-27001, SOC2, NIST frameworks
- **🏢 Organization Management**: Multi-tenant architecture with data isolation

### ✅ Technical Architecture
- **Frontend**: React.js + Tailwind CSS for modern, responsive UI
- **Backend**: Node.js (Express) with comprehensive API
- **ML Service**: Python FastAPI for AI/ML predictions
- **Database**: MongoDB for flexible data storage
- **Cache**: Redis for job queues and real-time data
- **Real-time**: Socket.IO for live updates
- **Containerization**: Docker + Docker Compose
- **Deployment**: Kubernetes-ready with health checks

## 🏗️ Architecture Overview

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   React.js      │    │   Node.js       │    │   Python        │
│   Frontend      │◄──►│   Backend       │◄──►│   ML Service    │
│   (Port 3000)   │    │   (Port 3001)   │    │   (Port 8001)   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │              ┌─────────────────┐              │
         │              │     Redis       │              │
         │              │  (Job Queues)   │              │
         │              └─────────────────┘              │
         │                       │                       │
         │              ┌─────────────────┐              │
         └──────────────│    MongoDB      │──────────────┘
                        │   (Database)    │
                        └─────────────────┘
```

## 📂 Project Structure

```
├── frontend/                  # React.js frontend application
│   ├── src/
│   │   ├── components/       # Reusable UI components
│   │   ├── pages/           # Application pages
│   │   ├── services/        # API service calls
│   │   ├── hooks/           # Custom React hooks
│   │   └── utils/           # Utility functions
│   ├── tailwind.config.js   # Tailwind CSS configuration
│   └── package.json
│
├── backend/                  # Node.js Express backend
│   ├── src/
│   │   ├── controllers/     # Request handlers
│   │   ├── routes/          # API route definitions
│   │   ├── middleware/      # Express middleware
│   │   ├── models/          # MongoDB schemas
│   │   ├── services/        # Business logic services
│   │   └── utils/           # Utility functions
│   └── package.json
│
├── ml-service/              # Python FastAPI ML service
│   ├── models/              # ML model definitions
│   ├── utils/               # Data processing utilities
│   ├── main.py              # FastAPI application
│   └── requirements.txt
│
├── shared/                  # Shared utilities and scripts
│   ├── vuln_scanners/       # Vulnerability scanning tools
│   ├── brute_sim/           # Brute force simulation scripts
│   └── pdf_generator/       # Report generation utilities
│
├── scripts/                 # Development and deployment scripts
│   ├── seed.js              # Database seeding
│   └── migrate.js           # Database migrations
│
├── docker-compose.yml       # Multi-service orchestration
├── .github/workflows/ci.yml # CI/CD pipeline
└── README.md               # This file
```

## 🚀 Quick Start

### Prerequisites

- **Node.js** >= 18.0.0
- **Python** >= 3.11
- **Docker** & **Docker Compose**
- **MongoDB** (or use Docker)
- **Redis** (or use Docker)

### 1. Clone & Setup

```bash
# Clone the repository
git clone <repository-url>
cd cybersecurity-platform

# Copy environment configuration
cp .env.example .env

# Install all dependencies
npm run install:all
```

### 2. Configure Environment

Edit `.env` file with your configuration:

```bash
# Database
MONGODB_URI=mongodb://localhost:27017/cybersecurity_platform
REDIS_HOST=localhost

# Security
JWT_SECRET=your-super-secret-jwt-key
ENCRYPTION_KEY=your-32-character-encryption-key

# External Services
STRIPE_SECRET_KEY=sk_test_your_stripe_secret_key
TELEGRAM_BOT_TOKEN=your-telegram-bot-token
SLACK_WEBHOOK_URL=your-slack-webhook-url

# Email Configuration
EMAIL_USER=your-email@domain.com
EMAIL_PASSWORD=your-app-password
```

### 3. Development Setup

```bash
# Start all services with Docker
npm run dev

# Or start individual services
npm run dev:frontend    # React frontend
npm run dev:backend     # Node.js backend  
npm run dev:ml          # Python ML service
```

### 4. Production Deployment

```bash
# Build and start with Docker Compose
docker-compose up -d

# Or build for Kubernetes
kubectl apply -f k8s/
```

## 📖 API Documentation

### Authentication Endpoints

```http
POST /api/auth/register     # User registration
POST /api/auth/login        # User login
POST /api/auth/logout       # User logout
POST /api/auth/forgot-password  # Password reset
```

### Core Platform Endpoints

```http
# Targets Management
GET    /api/targets         # List scan targets
POST   /api/targets         # Create new target
GET    /api/targets/:id     # Get target details
PATCH  /api/targets/:id     # Update target
DELETE /api/targets/:id     # Delete target

# Vulnerability Scans
GET    /api/scans           # List scans
POST   /api/scans           # Start new scan
GET    /api/scans/:id       # Get scan results
PATCH  /api/scans/:id       # Update scan
DELETE /api/scans/:id       # Delete scan

# Reports
GET    /api/reports         # List reports
POST   /api/reports         # Generate report
GET    /api/reports/:id/download  # Download PDF

# Analytics
GET    /api/analytics/dashboard    # Dashboard data
GET    /api/analytics/trends       # Trend analysis
GET    /api/analytics/vulnerabilities  # Vulnerability metrics
```

### DevSecOps Integration

```http
# CI/CD API for automated security checks
POST   /api/v1/scan         # Trigger automated scan
GET    /api/v1/status/:id   # Check scan status
GET    /api/v1/vulnerabilities/:id  # Get scan results
```

### ML Service Endpoints

```http
# AI/ML Predictions
POST   /ml/predict/risk              # Risk prediction
POST   /ml/analyze/vulnerabilities   # Vulnerability analysis
POST   /ml/intel/threat             # Threat intelligence lookup
POST   /ml/assess/compliance        # Compliance assessment
```

## 🔧 Configuration

### Database Models

The platform uses MongoDB with the following main collections:

- **Users**: Authentication, roles, billing, preferences
- **Targets**: Scan targets with network and security context
- **Scans**: Vulnerability scan results and metadata
- **Reports**: Generated security reports and analytics
- **PhishingCampaigns**: Training campaigns and user tracking

### Security Features

- **JWT Authentication**: Secure token-based authentication
- **Role-based Access Control**: Admin, Manager, Viewer permissions
- **Input Validation**: Comprehensive request validation
- **Rate Limiting**: API abuse prevention
- **Security Headers**: Helmet.js protection
- **Data Sanitization**: XSS and injection prevention

### Subscription Tiers

| Feature | Free | Basic | Professional | Enterprise |
|---------|------|-------|--------------|------------|
| Targets | 5 | 25 | 100 | Unlimited |
| Scans/Month | 10 | 100 | 500 | Unlimited |
| Reports | 5 | 25 | 100 | Unlimited |
| Users | 1 | 5 | 25 | Unlimited |
| API Access | ❌ | ✅ | ✅ | ✅ |
| Phishing Sim | ❌ | ✅ | ✅ | ✅ |
| AI Predictions | ❌ | ❌ | ✅ | ✅ |

## 🧪 Testing

```bash
# Run all tests
npm test

# Individual service tests
npm run test:frontend   # React component tests
npm run test:backend    # Node.js API tests
npm run test:ml         # Python ML service tests

# Coverage reports
npm run test:coverage
```

## 🚀 Deployment

### Docker Deployment

```bash
# Development
docker-compose up -d

# Production
docker-compose -f docker-compose.prod.yml up -d
```

### Kubernetes Deployment

```bash
# Apply Kubernetes manifests
kubectl apply -f k8s/

# Check deployment status
kubectl get pods -n cybersec-platform
```

### Environment Variables

Required environment variables for production:

```bash
NODE_ENV=production
MONGODB_URI=mongodb://mongo:27017/cybersecurity_platform
REDIS_HOST=redis
JWT_SECRET=<strong-secret-key>
ENCRYPTION_KEY=<32-character-key>
STRIPE_SECRET_KEY=<stripe-secret>
```

## 📊 Monitoring & Observability

### Health Checks

- **Frontend**: `http://localhost:3000`
- **Backend**: `http://localhost:3001/api/health`
- **ML Service**: `http://localhost:8001/health`

### Metrics & Logging

- **Winston Logging**: Structured logging with multiple transports
- **Prometheus Metrics**: Application and system metrics
- **Health Checks**: Kubernetes-ready liveness/readiness probes
- **Error Tracking**: Comprehensive error handling and reporting

## 🔒 Security Considerations

### Production Hardening

1. **Environment Variables**: Store secrets in secure key management
2. **HTTPS/TLS**: Enable SSL certificates for all communications
3. **Database Security**: Use authentication and encryption at rest
4. **Network Security**: Implement proper firewall rules
5. **Regular Updates**: Keep dependencies and base images updated

### Compliance

The platform supports compliance frameworks:

- **PCI-DSS**: Payment card industry standards
- **ISO 27001**: Information security management
- **SOC 2**: Service organization controls
- **NIST**: Cybersecurity framework
- **GDPR**: Data protection regulations

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines

- Follow ESLint configuration for JavaScript/TypeScript
- Use Black for Python code formatting
- Write tests for new features
- Update documentation as needed
- Follow semantic versioning

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

### Documentation

- **API Docs**: Available at `/api/docs` when running
- **ML Service Docs**: Available at `:8001/docs`
- **Architecture Guide**: See `docs/architecture.md`
- **Deployment Guide**: See `docs/deployment.md`

### Community

- **Issues**: Report bugs or request features
- **Discussions**: Community discussions and Q&A
- **Wiki**: Detailed documentation and guides

## 🙏 Acknowledgments

- **OWASP**: Security best practices and vulnerability data
- **NIST**: Cybersecurity framework and guidelines
- **CVE Database**: Vulnerability intelligence
- **Security Community**: Tools and methodologies

---

## 🔗 Quick Links

- [🎯 Live Demo](https://demo.cybersec-platform.com)
- [📚 Full Documentation](https://docs.cybersec-platform.com)
- [🐛 Report Issues](https://github.com/your-org/cybersec-platform/issues)
- [💬 Community Discord](https://discord.gg/cybersec-platform)
- [📧 Support Email](mailto:support@cybersec-platform.com)

**Built with ❤️ for the cybersecurity community**