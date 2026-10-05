from fastapi.testclient import TestClient

from backend.main import app
from backend.models import Flow
from backend.simulator import FlowSimulator, SCENARIOS
from backend.detector import PassiveDetector


def test_simulator_covers_all_scenarios():
    sim = FlowSimulator()
    for scenario in SCENARIOS:
        flow = sim.next_flow(scenario)
        assert "flow_id" in flow
        assert "src_ip" in flow
        assert "dst_ip" in flow
        assert "protocol" in flow


def test_detector_reset_clears_state():
    d = PassiveDetector()
    assert d.alert_history == []
    d.process(
        Flow(
            flow_id="x",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            protocol="TCP",
            tcp_flags="SYN",
            packets=1,
            in_bytes=0,
            out_bytes=60,
        ).model_dump()
    )
    assert len(d.alert_history) == 1
    d.reset()
    assert d.alert_history == []
    assert d.total_flows == 0
    assert d.total_alerts == 0


def test_health_endpoint():
    client = TestClient(app)
    r = client.get("/api/health")
    assert r.status_code == 200
    body = r.json()
    assert body["version"] == "7.0"
    assert body["return_path"] is False
    assert body["read_only"] is True
    assert body["payload_decryption"] is False
    assert body["ai_ml"] is True
    assert body["threat_intelligence"] is True


def test_start_and_stop_simulation():
    client = TestClient(app)
    r = client.post(
        "/api/simulation/start",
        json={"scenario": "benign", "rate": 5, "seconds": 1},
    )
    assert r.status_code == 200
    assert r.json().get("run_id")
    stop = client.post("/api/simulation/stop")
    assert stop.status_code == 200
    assert stop.json()["status"] in {"stopping", "not_running"}
