from backend.detector import PassiveDetector
from backend.simulator import FlowSimulator, generate


def test_benign_has_no_alert():
    d = PassiveDetector()
    for f in generate("benign", 100):
        assert d.process(f) is None


def test_syn_flood_alert():
    d = PassiveDetector()
    alert = d.process(generate("syn_flood", 1)[0])
    assert alert is not None
    assert alert["threat_class"] == "SYN flood"


def test_dns_tunnel_alert():
    d = PassiveDetector()
    alert = d.process(generate("dns_tunnel", 1)[0])
    assert alert is not None
    assert alert["threat_class"] == "DNS tunnelling"


def test_dga_alert():
    d = PassiveDetector()
    alert = d.process(generate("dga", 1)[0])
    assert alert is not None
    assert alert["threat_class"] == "DGA domain anomaly"


def test_data_exfiltration_alert():
    d = PassiveDetector()
    alert = d.process(generate("data_exfiltration", 1)[0])
    assert alert is not None
    assert alert["threat_class"] == "Possible data exfiltration"
    assert alert["evidence"]["detection_method"] == "behavioural_rule"


def test_udp_amplification_alert():
    d = PassiveDetector()
    alert = d.process(
        {
            "flow_id": "u",
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "protocol": "UDP",
            "packets": 10,
            "out_bytes": 100,
            "in_bytes": 6000,
            "dst_port": 53,
        }
    )
    assert alert is not None
    assert alert["threat_class"] == "UDP amplification"


def test_scan_alert_after_port_fanout():
    d = PassiveDetector()
    alerts = [d.process(f) for f in generate("scan", 25)]
    scan_alerts = [a for a in alerts if a and a["threat_class"] == "Recon / port scan"]
    assert scan_alerts, "Port scan should be detected after unique destination ports accumulate"
    assert scan_alerts[-1]["evidence"]["unique_destination_ports"] >= 5


def test_tls_anomaly_alert():
    d = PassiveDetector()
    alert = d.process(generate("tls_anomaly", 1)[0])
    assert alert is not None
    assert alert["threat_class"] == "Encrypted-session metadata anomaly"


def test_benign_does_not_trigger_exfiltration():
    d = PassiveDetector()
    sim = FlowSimulator()
    for _ in range(100):
        a = d.process(sim.next_flow("benign"))
        if a:
            assert a["threat_class"] != "Possible data exfiltration"
