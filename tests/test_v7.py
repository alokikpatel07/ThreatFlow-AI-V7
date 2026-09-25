import json
from pathlib import Path
from fastapi.testclient import TestClient
from backend.main import app
from backend.simulator import FlowSimulator
from backend.detector import PassiveDetector

def test_v7_health_and_ml():
    c=TestClient(app); h=c.get('/api/health').json(); assert h['version']=='7.0'; assert h['ai_ml'] is True; assert h['threat_intelligence'] is True
    m=c.get('/api/ml').json(); assert m['trained'] is True; assert m['model']=='RandomForest'; assert m['evaluation']['f1_weighted']>=0.95

def test_v7_threat_intel_endpoint():
    x=TestClient(app).get('/api/threat-intelligence').json(); assert x['ips']>=1 and x['domains']>=1

def test_v7_ml_detects_data_exfiltration():
    d=PassiveDetector(); f=FlowSimulator().next_flow('data_exfiltration'); a=d.process(f); assert a and a['threat_class']=='Possible data exfiltration'; assert a['evidence']['detection_method']=='behavioural_rule'

def test_v7_benign_no_alert():
    d=PassiveDetector(); s=FlowSimulator(); assert all(d.process(s.next_flow('benign')) is None for _ in range(100))
