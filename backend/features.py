from __future__ import annotations
import math
from typing import Dict

PROTOCOLS = ["TCP", "UDP", "ICMP", "QUIC", "IP"]

def entropy(s: str) -> float:
    if not s: return 0.0
    counts = {c:s.count(c) for c in set(s)}; n=len(s)
    return -sum((v/n)*math.log2(v/n) for v in counts.values())

def ngram_diversity(s: str, n=3) -> float:
    if len(s)<n: return 0.0
    grams={s[i:i+n] for i in range(len(s)-n+1)}
    return len(grams)/(len(s)-n+1)

def extract_features(f: dict) -> Dict[str,float]:
    outb=max(0,int(f.get('out_bytes',f.get('bytes_out',0)) or 0)); inb=max(0,int(f.get('in_bytes',f.get('bytes_in',0)) or 0))
    packets=max(1,int(f.get('packets',1) or 1)); duration=max(0,float(f.get('duration_ms',0) or 0))
    dns=str(f.get('dns_name') or f.get('dns_query') or ''); label=dns.split('.')[0] if dns else ''
    protocol=str(f.get('protocol','')).upper(); tls=str(f.get('tls_fingerprint') or '')
    flags=str(f.get('tcp_flags') or '').upper()
    ratio=outb/max(inb,1); amp=inb/max(outb,1)
    return {
      'out_bytes':float(outb),'in_bytes':float(inb),'total_bytes':float(outb+inb),
      'packets':float(packets),'duration_ms':duration,'bytes_per_packet':(outb+inb)/packets,
      'out_in_ratio':min(ratio,1000.0),'in_out_ratio':min(amp,1000.0),
      'dns_length':float(len(dns)),'dns_entropy':entropy(label),'ngram_diversity':ngram_diversity(label),
      'tls_anomaly':1.0 if tls.startswith(('RARE','JA4-C2')) else 0.0,
      'has_dns':1.0 if dns else 0.0,'is_tcp':1.0 if protocol=='TCP' else 0.0,'is_udp':1.0 if protocol=='UDP' else 0.0,
      'is_quic':1.0 if protocol=='QUIC' or 'QUIC' in protocol else 0.0,
      'syn':1.0 if 'SYN' in flags else 0.0,'ack':1.0 if 'ACK' in flags else 0.0,
      'dns_txt':1.0 if str(f.get('dns_record_type','')).upper()=='TXT' else 0.0,
    }
FEATURE_NAMES=list(extract_features({'protocol':'TCP'}).keys())
