# 🛡️ AI-Powered Cybersecurity Risk Simulation Web Platform

A comprehensive, production-ready cybersecurity platform that provides automated vulnerability scanning, risk assessment, and AI-powered threat prediction for modern DevSecOps workflows.

## 🚀 Features

### Core Security Features
- **Vulnerability Scanning**: Custom Nmap/Nikto scripts for comprehensive security assessment
- **Safe Brute Force Simulation**: Controlled testing on FTP, SSH, and HTTP login forms
- **AI/ML Risk Prediction**: Machine learning models for future threat probability analysis
- **Real-time Monitoring**: Live charts and heatmap dashboards for threat visualization

### Platform Features
- **Multi-user Support**: Role-based access control (Admin, Manager, Viewer)
- **Target Management**: Manage domains, IPs, and services for scanning
- **PDF Report Generation**: Downloadable professional security reports
- **Real-time Alerts**: Telegram & Slack notifications for critical risks
- **Phishing Simulation**: Consent-based training with email campaigns

### Enterprise Features
- **CI/CD Integration**: DevSecOps API for automated pre-deployment checks
- **SaaS Billing**: Stripe/PayPal integration for subscription management
- **Scalable Architecture**: Kubernetes-ready containerized deployment
- **Audit Logging**: Comprehensive security event tracking

## 🏗️ Architecture

### Tech Stack
- **Frontend**: React.js + Tailwind CSS
- **Backend**: Node.js (Express) + Python (FastAPI) microservice
- **Database**: MongoDB for data persistence
- **Cache**: Redis for job queues and session management
- **Real-time**: Socket.IO for live updates
- **Containerization**: Docker + Docker Compose
- **Orchestration**: Kubernetes ready

### Service Architecture
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   React App     │    │  Node.js API    │    │  Python ML      │
│   (Frontend)    │◄──►│   (Backend)     │◄──►│   (FastAPI)     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │                       ▼                       │
         │              ┌─────────────────┐              │
         │              │     MongoDB     │              │
         │              │   (Database)    │              │
         │              └─────────────────┘              │
         │                       │                       │
         │                       ▼                       │
         └──────────────►┌─────────────────┐◄────────────┘
                         │      Redis      │
                         │    (Cache)      │
                         └─────────────────┘
```

## 🚀 Quick Start

### Prerequisites
- Docker & Docker Compose
- Node.js 18+ (for development)
- Python 3.9+ (for development)

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd cybersec-platform
   ```

2. **Configure environment**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

3. **Start with Docker Compose**
   ```bash
   docker-compose up -d
   ```

4. **Access the platform**
   - Frontend: http://localhost:3000
   - Backend API: http://localhost:5000
   - ML Service: http://localhost:8000

### Development Setup

1. **Backend (Node.js)**
   ```bash
   cd backend
   npm install
   npm run dev
   ```

2. **Frontend (React)**
   ```bash
   cd frontend
   npm install
   npm start
   ```

3. **ML Service (Python)**
   ```bash
   cd ml-service
   pip install -r requirements.txt
   uvicorn main:app --reload
   ```

## 📚 API Documentation

### Authentication Endpoints
- `POST /api/auth/register` - User registration
- `POST /api/auth/login` - User login
- `POST /api/auth/logout` - User logout
- `GET /api/auth/profile` - Get user profile

### Target Management
- `GET /api/targets` - List user targets
- `POST /api/targets` - Add new target
- `PUT /api/targets/:id` - Update target
- `DELETE /api/targets/:id` - Delete target

### Scanning Endpoints
- `POST /api/scans/vulnerability` - Start vulnerability scan
- `POST /api/scans/brute-force` - Start brute force simulation
- `GET /api/scans/:id` - Get scan results
- `GET /api/scans/history` - Get scan history

### ML Predictions
- `POST /api/ml/predict-risk` - Get AI risk prediction
- `GET /api/ml/threat-trends` - Get threat trend analysis

### Reports & Alerts
- `GET /api/reports/:id/pdf` - Download PDF report
- `POST /api/alerts/configure` - Configure alert settings

## 🔧 Configuration

### Environment Variables

Key configuration options in `.env`:

- **Database**: MongoDB connection and Redis settings
- **Authentication**: JWT secrets and session configuration
- **Integrations**: Stripe, Telegram, Slack API keys
- **Security**: Scanner paths and rate limiting
- **ML**: Model training and prediction settings

### Security Configuration

The platform implements multiple security layers:

- **Input Validation**: Joi/Zod schemas for all inputs
- **Rate Limiting**: Configurable per-endpoint limits
- **CORS Protection**: Strict origin controls
- **JWT Authentication**: Secure token-based auth
- **Audit Logging**: Comprehensive activity tracking

## 🧪 Testing

### Running Tests
```bash
# Backend tests
cd backend && npm test

# Frontend tests
cd frontend && npm test

# ML service tests
cd ml-service && python -m pytest
```

### Test Coverage
- Unit tests for all core functions
- Integration tests for API endpoints
- End-to-end tests for critical workflows
- Security testing for vulnerability scanning

## 🚀 Deployment

### Docker Deployment
```bash
docker-compose -f docker-compose.prod.yml up -d
```

### Kubernetes Deployment
```bash
kubectl apply -f k8s/
```

### CI/CD Pipeline
GitHub Actions automatically:
- Runs tests on all components
- Builds and pushes Docker images
- Deploys to staging/production
- Performs security scans

## 🔒 Security Considerations

### Scanning Safety
- All scans are rate-limited and logged
- Brute force simulations use safe, controlled methods
- Target validation prevents unauthorized scanning
- Scan results are encrypted at rest

### Data Protection
- User data encrypted with AES-256
- Secure password hashing with bcrypt
- PII anonymization in logs
- GDPR compliant data handling

### Access Control
- Role-based permissions (Admin/Manager/Viewer)
- API key authentication for CI/CD
- Session management with Redis
- Audit trails for all sensitive operations

## 📊 Monitoring & Observability

### Metrics Collection
- Application performance monitoring
- Security event tracking
- User activity analytics
- System resource monitoring

### Alerting
- Real-time threat notifications
- System health alerts
- Performance degradation warnings
- Security incident notifications

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Documentation**: [docs.example.com](https://docs.example.com)
- **Issues**: [GitHub Issues](https://github.com/org/repo/issues)
- **Discord**: [Community Chat](https://discord.gg/cybersec)
- **Email**: support@cybersec-platform.com

## 🗺️ Roadmap

### Q1 2024
- [ ] Advanced ML threat prediction models
- [ ] Integration with popular SIEM tools
- [ ] Mobile app for iOS/Android

### Q2 2024
- [ ] Automated penetration testing
- [ ] Compliance reporting (SOC2, ISO27001)
- [ ] Multi-cloud deployment support

### Q3 2024
- [ ] AI-powered incident response
- [ ] Advanced phishing simulation campaigns
- [ ] Threat intelligence integration

---

**⚠️ Disclaimer**: This platform is designed for authorized security testing only. Users are responsible for ensuring they have proper permission before scanning any targets. The platform includes safety measures but should be used responsibly and in compliance with applicable laws and regulations.