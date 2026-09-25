from fastapi.testclient import TestClient
from backend.main import app

def test_scenarios_and_default_duration():
    c=TestClient(app)
    assert c.get("/api/scenarios").status_code == 200
    r=c.post("/api/simulation/start",json={"scenario":"benign","rate":2,"seconds":0})
    assert r.status_code == 200
    assert r.json()["duration_mode"]=="continuous_until_stop"
    c.post("/api/simulation/stop")

def test_run_events_endpoint_exists():
    c=TestClient(app)
    r=c.get("/api/runs")
    assert r.status_code==200
