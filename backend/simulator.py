from __future__ import annotations

import random
import time
import uuid

SCENARIOS = [
    "benign",
    "mixed",
    "syn_flood",
    "beacon",
    "dga",
    "dns_tunnel",
    "tls_anomaly",
    "scan",
    "data_exfiltration",
]


class FlowSimulator:
    """Purely synthetic, socket-free traffic generator."""

    def __init__(self):
        self._scan_counter = 0

    def next_flow(self, scenario: str) -> dict:
        if scenario not in SCENARIOS:
            raise ValueError(f"Unsupported scenario: {scenario}")

        if scenario == "mixed":
            # Keep normal traffic present in every mixed run.
            scenario = random.choices(
                [
                    "benign",
                    "syn_flood",
                    "beacon",
                    "dga",
                    "dns_tunnel",
                    "tls_anomaly",
                    "scan",
                    "data_exfiltration",
                ],
                weights=[55, 8, 7, 6, 6, 6, 7, 5],
                k=1,
            )[0]

        if scenario == "benign":
            out_bytes = random.randint(1000, 8000)
            # Keep ordinary UDP traffic below the amplification threshold.
            in_bytes = random.randint(500, max(500, out_bytes * 8))
            return _flow(
                dst_port=random.choice([53, 80, 443, 123, 22]),
                protocol=random.choice(["TCP", "UDP"]),
                packets=random.randint(8, 60),
                out_bytes=out_bytes,
                in_bytes=in_bytes,
                duration_ms=random.randint(50, 5000),
                tcp_flags="ACK",
            )

        if scenario == "syn_flood":
            return _flow(
                dst_port=80,
                protocol="TCP",
                packets=random.randint(1, 3),
                out_bytes=random.randint(40, 180),
                in_bytes=0,
                duration_ms=random.randint(1, 20),
                tcp_flags="SYN",
            )

        if scenario == "beacon":
            return _flow(
                dst_ip="10.10.0.90",
                dst_port=443,
                protocol="TCP",
                packets=3,
                out_bytes=180,
                in_bytes=240,
                duration_ms=1000,
                tcp_flags="ACK",
            )

        if scenario == "dga":
            chars = "abcdefghijklmnopqrstuvwxyz0123456789"
            name = "".join(random.choice(chars) for _ in range(random.randint(20, 28))) + ".com"
            return _flow(
                dst_port=53,
                protocol="UDP",
                packets=2,
                out_bytes=120,
                in_bytes=180,
                dns_name=name,
                dns_record_type="A",
            )

        if scenario == "dns_tunnel":
            chars = "abcdefghijklmnopqrstuvwxyz0123456789"
            name = "".join(random.choice(chars) for _ in range(55)) + ".tunnel.example"
            return _flow(
                dst_port=53,
                protocol="UDP",
                packets=2,
                out_bytes=500,
                in_bytes=180,
                dns_name=name,
                dns_record_type="TXT",
            )

        if scenario == "tls_anomaly":
            return _flow(
                dst_port=443,
                protocol="TCP",
                packets=random.randint(5, 20),
                out_bytes=500,
                in_bytes=700,
                tls_fingerprint="RARE-JA4-C2",
            )

        if scenario == "scan":
            self._scan_counter += 1
            return _flow(
                src_ip="10.10.0.30",
                dst_ip=f"10.10.0.{20 + (self._scan_counter % 8)}",
                dst_port=10000 + self._scan_counter,
                protocol="TCP",
                packets=1,
                out_bytes=60,
                in_bytes=0,
                duration_ms=1,
                tcp_flags="FIN",
            )

        if scenario == "data_exfiltration":
            return _flow(
                src_ip="10.10.0.50",
                dst_ip="10.10.0.80",
                dst_port=443,
                protocol="TCP",
                packets=500,
                out_bytes=2000000,
                in_bytes=1000,
                duration_ms=30000,
                tcp_flags="ACK",
            )

        raise ValueError(f"Unsupported scenario: {scenario}")


def _flow(**kw) -> dict:
    base = dict(
        timestamp=time.time(),
        flow_id=uuid.uuid4().hex[:12],
        src_ip="10.10.0.10",
        dst_ip="10.10.0.20",
        src_port=random.randint(1024, 65535),
        dst_port=443,
        protocol="TCP",
        packets=20,
        out_bytes=1800,
        in_bytes=2200,
        duration_ms=random.randint(20, 500),
        tcp_flags="ACK",
        dns_name="",
        dns_record_type="",
        tls_fingerprint="",
    )
    base.update(kw)
    return base


def generate(scenario: str, n: int):
    sim = FlowSimulator()
    return [sim.next_flow(scenario) for _ in range(n)]
