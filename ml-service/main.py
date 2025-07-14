from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
import os
import logging
import joblib
from pathlib import Path
import uvicorn

# Import custom modules
from models.risk_predictor import RiskPredictor
from models.vulnerability_analyzer import VulnerabilityAnalyzer
from models.threat_intelligence import ThreatIntelligence
from utils.data_processor import DataProcessor
from utils.feature_extractor import FeatureExtractor

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Cybersecurity ML Service",
    description="AI-Powered Risk Prediction and Vulnerability Analysis Service",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Pydantic models for request/response
class VulnerabilityData(BaseModel):
    id: str
    name: str
    severity: str = Field(..., regex="^(critical|high|medium|low|info)$")
    cvss_score: Optional[float] = Field(None, ge=0, le=10)
    cve_ids: List[str] = []
    cwe_ids: List[str] = []
    description: str
    affected_services: List[str] = []
    exploit_available: bool = False
    patch_available: bool = False
    discovery_date: datetime
    last_seen: datetime

class TargetData(BaseModel):
    id: str
    type: str = Field(..., regex="^(domain|ip|url|network_range)$")
    value: str
    ports: List[Dict[str, Any]] = []
    services: List[Dict[str, Any]] = []
    technology_stack: List[str] = []
    location: Optional[Dict[str, str]] = None
    reputation: str = Field("neutral", regex="^(good|neutral|suspicious|malicious)$")
    exposure_level: str = Field("medium", regex="^(low|medium|high|critical)$")

class ScanData(BaseModel):
    id: str
    target_id: str
    scan_type: str
    vulnerabilities: List[VulnerabilityData]
    scan_date: datetime
    scan_duration: int  # in seconds
    coverage: float = Field(ge=0, le=100)  # percentage
    tools_used: List[str] = []

class RiskPredictionRequest(BaseModel):
    target: TargetData
    vulnerabilities: List[VulnerabilityData]
    historical_scans: List[ScanData] = []
    threat_intelligence: Optional[Dict[str, Any]] = None

class RiskPredictionResponse(BaseModel):
    overall_risk_score: float = Field(ge=0, le=100)
    risk_level: str
    confidence: float = Field(ge=0, le=1)
    attack_probability: float = Field(ge=0, le=1)
    time_to_compromise: Optional[int] = None  # days
    critical_vulnerabilities: int
    exploitable_vulnerabilities: int
    recommendations: List[str]
    threat_actors: List[str]
    predicted_attack_vectors: List[str]
    model_version: str
    prediction_timestamp: datetime

class ThreatIntelligenceRequest(BaseModel):
    indicators: List[str]  # IPs, domains, hashes, etc.
    indicator_types: List[str]  # ip, domain, hash, url
    context: Optional[Dict[str, Any]] = None

class ComplianceAssessmentRequest(BaseModel):
    vulnerabilities: List[VulnerabilityData]
    standards: List[str] = ["PCI-DSS", "ISO-27001", "SOC2", "NIST"]
    target_info: TargetData

# Global ML models and services
ml_models = {}
data_processor = None
feature_extractor = None
threat_intel = None

@app.on_event("startup")
async def startup_event():
    """Initialize ML models and services on startup"""
    global ml_models, data_processor, feature_extractor, threat_intel
    
    logger.info("Initializing ML service...")
    
    try:
        # Initialize data processor and feature extractor
        data_processor = DataProcessor()
        feature_extractor = FeatureExtractor()
        threat_intel = ThreatIntelligence()
        
        # Load or train ML models
        model_path = Path("models/trained")
        model_path.mkdir(parents=True, exist_ok=True)
        
        # Risk predictor model
        risk_predictor_path = model_path / "risk_predictor.joblib"
        if risk_predictor_path.exists():
            ml_models['risk_predictor'] = joblib.load(risk_predictor_path)
            logger.info("Loaded pre-trained risk predictor model")
        else:
            ml_models['risk_predictor'] = RiskPredictor()
            await ml_models['risk_predictor'].train_default_model()
            joblib.dump(ml_models['risk_predictor'], risk_predictor_path)
            logger.info("Trained new risk predictor model")
        
        # Vulnerability analyzer
        vuln_analyzer_path = model_path / "vulnerability_analyzer.joblib"
        if vuln_analyzer_path.exists():
            ml_models['vulnerability_analyzer'] = joblib.load(vuln_analyzer_path)
            logger.info("Loaded pre-trained vulnerability analyzer")
        else:
            ml_models['vulnerability_analyzer'] = VulnerabilityAnalyzer()
            await ml_models['vulnerability_analyzer'].train_default_model()
            joblib.dump(ml_models['vulnerability_analyzer'], vuln_analyzer_path)
            logger.info("Trained new vulnerability analyzer")
        
        logger.info("ML service initialization completed successfully")
        
    except Exception as e:
        logger.error(f"Failed to initialize ML service: {str(e)}")
        raise e

@app.get("/")
async def root():
    """Root endpoint with service information"""
    return {
        "service": "Cybersecurity ML Service",
        "version": "1.0.0",
        "status": "operational",
        "endpoints": {
            "health": "/health",
            "predict_risk": "/predict/risk",
            "analyze_vulnerabilities": "/analyze/vulnerabilities",
            "threat_intelligence": "/intel/threat",
            "compliance_assessment": "/assess/compliance",
            "model_info": "/models/info"
        },
        "documentation": "/docs"
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    try:
        model_status = {
            name: "loaded" if model is not None else "not_loaded"
            for name, model in ml_models.items()
        }
        
        return {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "models": model_status,
            "services": {
                "data_processor": "ready" if data_processor else "not_ready",
                "feature_extractor": "ready" if feature_extractor else "not_ready",
                "threat_intelligence": "ready" if threat_intel else "not_ready"
            },
            "version": "1.0.0"
        }
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return JSONResponse(
            status_code=503,
            content={
                "status": "unhealthy",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
        )

@app.post("/predict/risk", response_model=RiskPredictionResponse)
async def predict_risk(request: RiskPredictionRequest):
    """Predict cybersecurity risk based on vulnerabilities and target data"""
    try:
        if 'risk_predictor' not in ml_models:
            raise HTTPException(status_code=503, detail="Risk predictor model not available")
        
        # Extract features from the request data
        features = feature_extractor.extract_risk_features(
            target=request.target,
            vulnerabilities=request.vulnerabilities,
            historical_scans=request.historical_scans,
            threat_intelligence=request.threat_intelligence
        )
        
        # Make prediction
        prediction = ml_models['risk_predictor'].predict(features)
        
        # Calculate additional metrics
        critical_vulns = len([v for v in request.vulnerabilities if v.severity == 'critical'])
        exploitable_vulns = len([v for v in request.vulnerabilities if v.exploit_available])
        
        # Generate recommendations
        recommendations = _generate_recommendations(request.vulnerabilities, prediction)
        
        # Determine risk level
        risk_level = _calculate_risk_level(prediction['risk_score'])
        
        return RiskPredictionResponse(
            overall_risk_score=prediction['risk_score'],
            risk_level=risk_level,
            confidence=prediction['confidence'],
            attack_probability=prediction['attack_probability'],
            time_to_compromise=prediction.get('time_to_compromise'),
            critical_vulnerabilities=critical_vulns,
            exploitable_vulnerabilities=exploitable_vulns,
            recommendations=recommendations,
            threat_actors=prediction.get('threat_actors', []),
            predicted_attack_vectors=prediction.get('attack_vectors', []),
            model_version="1.0.0",
            prediction_timestamp=datetime.utcnow()
        )
        
    except Exception as e:
        logger.error(f"Risk prediction failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Risk prediction failed: {str(e)}")

@app.post("/analyze/vulnerabilities")
async def analyze_vulnerabilities(vulnerabilities: List[VulnerabilityData]):
    """Analyze vulnerabilities for patterns and prioritization"""
    try:
        if 'vulnerability_analyzer' not in ml_models:
            raise HTTPException(status_code=503, detail="Vulnerability analyzer not available")
        
        # Convert vulnerabilities to feature vectors
        features = feature_extractor.extract_vulnerability_features(vulnerabilities)
        
        # Analyze with ML model
        analysis = ml_models['vulnerability_analyzer'].analyze(features)
        
        return {
            "analysis_timestamp": datetime.utcnow().isoformat(),
            "total_vulnerabilities": len(vulnerabilities),
            "severity_distribution": _calculate_severity_distribution(vulnerabilities),
            "priority_score": analysis['priority_score'],
            "exploit_likelihood": analysis['exploit_likelihood'],
            "patching_urgency": analysis['patching_urgency'],
            "attack_patterns": analysis.get('attack_patterns', []),
            "recommended_actions": analysis.get('recommended_actions', []),
            "similar_incidents": analysis.get('similar_incidents', [])
        }
        
    except Exception as e:
        logger.error(f"Vulnerability analysis failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Vulnerability analysis failed: {str(e)}")

@app.post("/intel/threat")
async def threat_intelligence_lookup(request: ThreatIntelligenceRequest):
    """Lookup threat intelligence for indicators"""
    try:
        results = await threat_intel.lookup_indicators(
            indicators=request.indicators,
            indicator_types=request.indicator_types,
            context=request.context
        )
        
        return {
            "lookup_timestamp": datetime.utcnow().isoformat(),
            "indicators_analyzed": len(request.indicators),
            "threat_intelligence": results,
            "summary": {
                "malicious_count": sum(1 for r in results if r.get('malicious', False)),
                "suspicious_count": sum(1 for r in results if r.get('suspicious', False)),
                "clean_count": sum(1 for r in results if r.get('clean', False)),
                "unknown_count": sum(1 for r in results if r.get('unknown', False))
            }
        }
        
    except Exception as e:
        logger.error(f"Threat intelligence lookup failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Threat intelligence lookup failed: {str(e)}")

@app.post("/assess/compliance")
async def assess_compliance(request: ComplianceAssessmentRequest):
    """Assess compliance against security standards"""
    try:
        compliance_scores = {}
        
        for standard in request.standards:
            score = _assess_compliance_standard(
                standard, 
                request.vulnerabilities, 
                request.target_info
            )
            compliance_scores[standard] = score
        
        overall_score = np.mean(list(compliance_scores.values()))
        
        return {
            "assessment_timestamp": datetime.utcnow().isoformat(),
            "overall_compliance_score": overall_score,
            "compliance_by_standard": compliance_scores,
            "compliance_level": _get_compliance_level(overall_score),
            "gaps_identified": _identify_compliance_gaps(request.vulnerabilities),
            "recommendations": _get_compliance_recommendations(compliance_scores),
            "next_assessment_date": (datetime.utcnow() + timedelta(days=90)).isoformat()
        }
        
    except Exception as e:
        logger.error(f"Compliance assessment failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Compliance assessment failed: {str(e)}")

@app.get("/models/info")
async def get_model_info():
    """Get information about loaded ML models"""
    model_info = {}
    
    for name, model in ml_models.items():
        if hasattr(model, 'get_info'):
            model_info[name] = model.get_info()
        else:
            model_info[name] = {
                "status": "loaded",
                "type": type(model).__name__
            }
    
    return {
        "models": model_info,
        "total_models": len(ml_models),
        "service_version": "1.0.0",
        "last_updated": datetime.utcnow().isoformat()
    }

@app.post("/models/retrain")
async def retrain_models(background_tasks: BackgroundTasks):
    """Trigger model retraining (background task)"""
    background_tasks.add_task(_retrain_models)
    
    return {
        "status": "retraining_started",
        "message": "Model retraining has been queued as a background task",
        "timestamp": datetime.utcnow().isoformat()
    }

# Helper functions
def _calculate_risk_level(risk_score: float) -> str:
    """Calculate risk level based on score"""
    if risk_score >= 80:
        return "critical"
    elif risk_score >= 60:
        return "high"
    elif risk_score >= 40:
        return "medium"
    elif risk_score >= 20:
        return "low"
    else:
        return "info"

def _generate_recommendations(vulnerabilities: List[VulnerabilityData], prediction: Dict) -> List[str]:
    """Generate security recommendations"""
    recommendations = []
    
    critical_count = len([v for v in vulnerabilities if v.severity == 'critical'])
    if critical_count > 0:
        recommendations.append(f"Immediately patch {critical_count} critical vulnerabilities")
    
    exploitable_count = len([v for v in vulnerabilities if v.exploit_available])
    if exploitable_count > 0:
        recommendations.append(f"Prioritize {exploitable_count} vulnerabilities with available exploits")
    
    if prediction['risk_score'] > 70:
        recommendations.append("Implement additional monitoring and intrusion detection")
        recommendations.append("Consider isolating high-risk assets")
    
    return recommendations

def _calculate_severity_distribution(vulnerabilities: List[VulnerabilityData]) -> Dict[str, int]:
    """Calculate vulnerability severity distribution"""
    distribution = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    
    for vuln in vulnerabilities:
        distribution[vuln.severity] += 1
    
    return distribution

def _assess_compliance_standard(standard: str, vulnerabilities: List[VulnerabilityData], target: TargetData) -> float:
    """Assess compliance for a specific standard"""
    # Placeholder compliance assessment logic
    base_score = 85.0
    
    # Deduct points for vulnerabilities
    for vuln in vulnerabilities:
        if vuln.severity == 'critical':
            base_score -= 10
        elif vuln.severity == 'high':
            base_score -= 5
        elif vuln.severity == 'medium':
            base_score -= 2
    
    return max(0, min(100, base_score))

def _get_compliance_level(score: float) -> str:
    """Get compliance level based on score"""
    if score >= 90:
        return "excellent"
    elif score >= 80:
        return "good"
    elif score >= 70:
        return "fair"
    elif score >= 60:
        return "poor"
    else:
        return "critical"

def _identify_compliance_gaps(vulnerabilities: List[VulnerabilityData]) -> List[str]:
    """Identify compliance gaps"""
    gaps = []
    
    if any(v.severity == 'critical' for v in vulnerabilities):
        gaps.append("Critical vulnerabilities present")
    
    if any(not v.patch_available for v in vulnerabilities):
        gaps.append("Unpatched vulnerabilities detected")
    
    return gaps

def _get_compliance_recommendations(compliance_scores: Dict[str, float]) -> List[str]:
    """Get compliance recommendations"""
    recommendations = []
    
    for standard, score in compliance_scores.items():
        if score < 80:
            recommendations.append(f"Improve {standard} compliance (current: {score:.1f}%)")
    
    return recommendations

async def _retrain_models():
    """Background task to retrain ML models"""
    try:
        logger.info("Starting model retraining...")
        
        # Retrain risk predictor
        if 'risk_predictor' in ml_models:
            await ml_models['risk_predictor'].retrain()
        
        # Retrain vulnerability analyzer
        if 'vulnerability_analyzer' in ml_models:
            await ml_models['vulnerability_analyzer'].retrain()
        
        logger.info("Model retraining completed successfully")
        
    except Exception as e:
        logger.error(f"Model retraining failed: {str(e)}")

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8001,
        reload=True,
        log_level="info"
    )