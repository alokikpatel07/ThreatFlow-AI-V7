# ThreatFlow AI / V7 Technical Documentation

## 1. Architecture
The prototype has three logical stages: traffic simulation, passive AI/ML detection, and threat classification/intelligence. All analysis is performed on observed metadata. There is no return communication path from the detector to a simulated or supplied traffic source.

## 2. AI/ML
A Random Forest classifier is trained from a reproducible labelled synthetic corpus covering benign, SYN flood, beacon, DGA, DNS tunnelling, TLS anomaly, scan, data exfiltration and UDP amplification classes. `evaluation/model_evaluation.json` records held-out accuracy, precision, recall, F1 and a confusion matrix. The detector combines ML probability with deterministic behavioural rules so safety-critical signatures remain explainable.

## 3. Public datasets
The SIH concept names CIC-IDS2017, CSE-CIC-IDS2018, UNSW-NB15 and DGArchive. These third-party datasets are not redistributed. `datasets/README.md` and `ml/train.py` provide the integration point for licensed copies and project-specific column mappings.

## 4. Features
Features include byte/packet volumes, directionality, ratios, duration, DNS length/entropy/n-gram diversity, DNS record type, TCP flags, TLS JA3/JA3S/JA4 where TShark exposes them, and QUIC version/SNI metadata. No encrypted payload is decrypted.

## 5. PCAP flow reconstruction
TShark is used only as an offline reader. Packets are grouped by a canonical bidirectional 5-tuple. Bytes are assigned to the first observed direction as outbound and reverse-direction bytes as inbound. This makes asymmetric-flow features meaningful for PCAP analysis while preserving the passive boundary.

## 6. Threat intelligence
A local IOC feed supports IP, domain and TLS-fingerprint matches. Matching IOCs are attached to alert evidence. The demo feed is intentionally small and must be replaced by an authorized production feed for deployment.

## 7. One-way scope
The software prototype does not implement a physical data diode. It implements the read-only analysis side of a one-directional monitoring architecture. A production deployment would connect this reader to an approved passive mirror or hardware one-way feed.

## 8. Limitations
Dataset adapters need column mappings for each downloaded public dataset. Model metrics are for the bundled synthetic validation corpus and must not be represented as real-world accuracy. QUIC/TLS metadata depends on the fields supported by the installed TShark version. The detector does not decrypt payloads.
