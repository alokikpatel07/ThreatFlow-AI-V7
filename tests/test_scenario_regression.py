from fastapi.testclient import TestClient
from backend.main import app
from backend.simulator import FlowSimulator, generate, SCENARIOS
from backend.detector import PassiveDetector


def test_scenario_list_removed_udp_and_uses_data_exfiltration():
    client = TestClient(app)
    scenarios = client.get('/api/scenarios').json()['scenarios']
    assert 'udp_amplification' not in scenarios
    assert 'exfil' not in scenarios
    assert 'data_exfiltration' in scenarios


def test_data_exfiltration_simulation_is_threat_only():
    sim = FlowSimulator()
    d = PassiveDetector()
    flows = [sim.next_flow('data_exfiltration') for _ in range(5)]
    assert all(f['out_bytes'] >= 1_000_000 for f in flows)
    assert all(f['in_bytes'] <= 2_000 for f in flows)
    alerts = [d.process(f) for f in flows]
    assert all(a and a['threat_class'] == 'Possible data exfiltration' for a in alerts)


def test_mixed_contains_data_exfiltration():
    sim = FlowSimulator()
    found = False
    for _ in range(500):
        if sim.next_flow('mixed')['out_bytes'] >= 1_000_000:
            found = True
            break
    assert found


def test_udp_amplification_detection_remains_available_for_observed_traffic():
    d = PassiveDetector()
    f = {'flow_id':'udp1','src_ip':'10.0.0.1','dst_ip':'10.0.0.2','protocol':'UDP',
         'packets':10,'out_bytes':100,'in_bytes':6000,'dst_port':53,'tcp_flags':''}
    a = d.process(f)
    assert a and a['threat_class'] == 'UDP amplification'


def test_scan_detection():
    d = PassiveDetector(); sim = FlowSimulator()
    alerts = [d.process(sim.next_flow('scan')) for _ in range(8)]
    assert any(a and a['threat_class'] == 'Recon / port scan' for a in alerts)


def test_benign_does_not_trigger_exfiltration():
    d = PassiveDetector(); sim = FlowSimulator()
    assert not any(d.process(sim.next_flow('benign')) and d.alert_history[-1]['threat_class']=='Possible data exfiltration' for _ in range(100))
