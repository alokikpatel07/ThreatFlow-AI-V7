from fastapi.testclient import TestClient

from backend.main import app
from backend.models import Flow
from backend.simulator import FlowSimulator
from backend.detector import PassiveDetector

def test_simulator_api_exists():
    sim = FlowSimulator()
    for scenario in ["benign", "mixed", "syn_flood",
                     "beacon", "dga", "dns_tunnel", "tls_anomaly", "scan", "data_exfiltration"]:
        flow = sim.next_flow(scenario)
        assert "flow_id" in flow
        assert "src_ip" in flow

def test_detector_initializes_and_reset_works():
    d = PassiveDetector()
    assert d.alert_history == []
    d.process(Flow(flow_id="x", src_ip="10.0.0.1", dst_ip="10.0.0.2",
                   protocol="TCP", tcp_flags="SYN", packets=1,
                   in_bytes=0, out_bytes=60).model_dump())
    assert len(d.alert_history) == 1
    d.reset()
    assert d.alert_history == []

def test_health():
    client = TestClient(app)
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["version"] == "7.0"
    assert r.json()["return_path"] is False

def test_start_and_stop_simulation():
    client = TestClient(app)
    r = client.post("/api/simulation/start",
                    json={"scenario": "benign", "rate": 5, "seconds": 1})
    assert r.status_code == 200
    run_id = r.json()["run_id"]
    assert run_id
    # The TestClient context waits for background tasks to settle.
