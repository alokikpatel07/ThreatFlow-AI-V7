from fastapi.testclient import TestClient

from backend.main import app


def test_scenarios_and_continuous_duration():
    c = TestClient(app)
    assert c.get("/api/scenarios").status_code == 200
    r = c.post(
        "/api/simulation/start",
        json={"scenario": "benign", "rate": 2, "seconds": 0},
    )
    assert r.status_code == 200
    assert r.json()["duration_mode"] == "continuous_until_stop"
    stop = c.post("/api/simulation/stop")
    assert stop.status_code == 200


def test_runs_endpoint():
    c = TestClient(app)
    r = c.get("/api/runs")
    assert r.status_code == 200
    assert "runs" in r.json()


def test_ml_endpoint():
    c = TestClient(app)
    m = c.get("/api/ml").json()
    assert m["trained"] is True
    assert m["model"] == "RandomForest"
    assert m["evaluation"]["f1_weighted"] >= 0.95


def test_threat_intelligence_endpoint():
    x = TestClient(app).get("/api/threat-intelligence").json()
    assert x["ips"] >= 1
    assert x["domains"] >= 1
