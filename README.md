# One-Way Passive Threat Detection — V7 FINAL

Version 7 implements the full technical approach described in the SIH concept while keeping the passive/read-only safety boundary.

## V7 architecture
1. **Traffic simulation** — deterministic benign and threat flow generation, including data exfiltration; no sockets or return traffic.
2. **Passive feature extraction** — flow, timing, DNS, TLS/JA3/JA3S/JA4 where exposed by TShark, and QUIC metadata.
3. **Hybrid AI/ML detection** — Random Forest inference plus deterministic behavioural rules for high-confidence signatures. The bundled model is trained on a reproducible labelled synthetic corpus; public-dataset adapters are included without redistributing third-party datasets.
4. **Threat intelligence** — local IOC feed enrichment for IPs, domains and TLS fingerprints.
5. **Explainable alerts** — threat class, confidence, severity, evidence, detection method and IOC matches.
6. **PCAP flow reconstruction** — offline bidirectional 5-tuple aggregation before detection; no packets are transmitted.
7. **Evaluation** — accuracy, precision, recall, F1 and confusion matrix are written to `evaluation/model_evaluation.json`.
8. **Latency** — detector processing latency and end-to-end application processing latency are recorded per event.

## Threats
SYN flood, UDP amplification (observed/PCAP only; not a simulator option), C2 beaconing, DGA, DNS tunnelling, encrypted-session anomalies, reconnaissance/port scanning and data exfiltration.

## Safety boundary
The application is a passive detector. It does not open sockets to the monitored environment, send probes, complete handshakes, block traffic, or decrypt TLS/QUIC payloads. The software simulator models the observation side of a one-directional architecture; it is not a physical data diode.

## Run
```bash
python -m pip install -r requirements.txt
python run.py
```
Open `http://127.0.0.1:8000`.

## Duration
`0` means continuous simulation until Stop. A positive value runs for that many seconds.

## PCAP
Install Wireshark/TShark and ensure `tshark --version` works. Upload `.pcap`, `.pcapng` or `.cap` from the dashboard. V7 reconstructs bidirectional flows offline from the capture and then runs the detector.

## Model / datasets
`ml/model.py` trains the bundled reproducible Random Forest. `ml/train.py` accepts a CSV label column (`label`, `class`, `attack`, or `category`) as the starting point for project-specific dataset mappings. The repository does not redistribute CIC-IDS2017, CSE-CIC-IDS2018, UNSW-NB15 or DGArchive; place licensed copies under `datasets/` and adapt mappings as required.

## Threat intelligence
`threat_intel/iocs.json` is a small demo IOC feed. Replace/extend it with an authorized feed for deployment. No external service is contacted by the prototype.

## Tests
Run:
```bash
pytest -q
```
