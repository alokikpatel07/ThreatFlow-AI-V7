from fastapi.testclient import TestClient

from backend.main import app
from backend.simulator import FlowSimulator
from backend.detector import PassiveDetector


def test_scenario_list_has_data_exfiltration_not_udp():
    client = TestClient(app)
    scenarios = client.get("/api/scenarios").json()["scenarios"]
    assert "udp_amplification" not in scenarios
    assert "exfil" not in scenarios
    assert "data_exfiltration" in scenarios
    assert "benign" in scenarios
    assert "mixed" in scenarios


def test_data_exfiltration_flow_volumes():
    sim = FlowSimulator()
    d = PassiveDetector()
    flows = [sim.next_flow("data_exfiltration") for _ in range(5)]
    assert all(f["out_bytes"] >= 1_000_000 for f in flows)
    assert all(f["in_bytes"] <= 2_000 for f in flows)
    alerts = [d.process(f) for f in flows]
    assert all(a and a["threat_class"] == "Possible data exfiltration" for a in alerts)


def test_mixed_can_emit_data_exfiltration():
    sim = FlowSimulator()
    found = False
    for _ in range(500):
        if sim.next_flow("mixed")["out_bytes"] >= 1_000_000:
            found = True
            break
    assert found
