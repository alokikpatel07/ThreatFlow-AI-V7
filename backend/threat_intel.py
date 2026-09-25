from __future__ import annotations
from pathlib import Path
import json
ROOT=Path(__file__).resolve().parent.parent
IOC_PATH=ROOT/'threat_intel'/'iocs.json'

def load_iocs():
    try: return json.loads(IOC_PATH.read_text(encoding='utf-8'))
    except Exception: return {'ips':{},'domains':{},'tls_fingerprints':{}}

def enrich(flow:dict):
    db=load_iocs(); matches=[]
    src=flow.get('src_ip',''); dst=flow.get('dst_ip',''); dns=flow.get('dns_name') or flow.get('dns_query') or ''; tls=flow.get('tls_fingerprint') or ''
    if src in db.get('ips',{}): matches.append({'type':'source_ip','value':src,'context':db['ips'][src]})
    if dst in db.get('ips',{}): matches.append({'type':'destination_ip','value':dst,'context':db['ips'][dst]})
    if dns in db.get('domains',{}): matches.append({'type':'domain','value':dns,'context':db['domains'][dns]})
    if tls in db.get('tls_fingerprints',{}): matches.append({'type':'tls_fingerprint','value':tls,'context':db['tls_fingerprints'][tls]})
    return matches
