from __future__ import annotations
from collections import defaultdict, deque
import math
from .features import entropy, ngram_diversity
from .threat_intel import enrich

class PassiveDetector:
    """Hybrid passive detector: deterministic behavioural rules + ML classification + local IOC enrichment.
    It never opens sockets, probes, blocks, modifies traffic, or decrypts payloads.
    """
    def __init__(self, enable_ml=True):
        self.dst_ports=defaultdict(lambda:deque(maxlen=512)); self.dst_hosts=defaultdict(lambda:deque(maxlen=512))
        self.pair_times=defaultdict(lambda:deque(maxlen=16)); self.pair_count=defaultdict(int)
        self.total_flows=0; self.total_alerts=0; self.alert_history=[]; self.enable_ml=enable_ml; self._ml=None
        if enable_ml:
            try:
                from ml.model import predict_flow
                self._ml=predict_flow
            except Exception: self._ml=None
    def reset(self):
        self.total_flows=0; self.total_alerts=0; self.alert_history.clear(); self.pair_count.clear(); self.dst_ports.clear(); self.dst_hosts.clear(); self.pair_times.clear()
    def process(self,f:dict):
        self.total_flows+=1; src,dst=f['src_ip'],f['dst_ip']; key=(src,dst); self.pair_count[key]+=1
        self.dst_ports[src].append(int(f.get('dst_port',0))); self.dst_hosts[src].append(dst)
        ts=float(f.get('timestamp') or 0); self.pair_times[key].append(ts)
        def add(threat,confidence,severity,evidence,method='behavioural_rule'):
            ti=enrich(f); evidence=dict(evidence); evidence['detection_method']=method
            if ti: evidence['threat_intelligence_matches']=ti
            alert={'timestamp':f.get('timestamp'),'flow_id':f['flow_id'],'threat_class':threat,'severity':severity,'confidence':round(min(0.99,confidence),2),'evidence':evidence,'src_ip':src,'dst_ip':dst}
            self.alert_history.append(alert); self.total_alerts+=1; return alert
        packets=int(f.get('packets',1)); outb=int(f.get('out_bytes',f.get('bytes_out',0)) or 0); inb=int(f.get('in_bytes',f.get('bytes_in',0)) or 0)
        protocol=str(f.get('protocol','')).upper(); flags=str(f.get('tcp_flags','')).upper(); ratio=outb/max(inb,1); amp=inb/max(outb,1)
        dns=f.get('dns_name') or f.get('dns_query') or ''; label=dns.split('.')[0] if dns else ''; ent=entropy(label); ng=ngram_diversity(label); tls=f.get('tls_fingerprint') or ''
        unique_ports=len({p for p in self.dst_ports[src] if p>0}); unique_hosts=len(set(self.dst_hosts[src]))
        if (unique_ports>=5 and (flags in {'FIN','SYN','SYN,FIN'} or packets<=3)) or unique_hosts>=10:
            return add('Recon / port scan',.95,'high',{'unique_destination_ports':unique_ports,'unique_destination_hosts':unique_hosts})
        if protocol=='UDP' and outb>0 and inb>=3000 and amp>=10:
            return add('UDP amplification',.97,'critical',{'in_out_ratio':round(amp,1),'bytes_out':outb,'bytes_in':inb})
        if 'SYN' in flags and packets<=3 and inb==0:
            return add('SYN flood',.94,'critical',{'packets':packets,'bytes_in':inb,'tcp_flags':flags})
        if outb>=100000 and ratio>=10:
            return add('Possible data exfiltration',.93,'high',{'out_in_ratio':round(ratio,1),'bytes_out':outb,'bytes_in':inb})
        if dns and len(dns)>=45 and ent>=3.5:
            return add('DNS tunnelling',.92,'high',{'dns_length':len(dns),'dns_entropy':round(ent,2),'record_type':f.get('dns_record_type')})
        if dns and len(dns)>=20 and ent>=3.0 and ng>=.70:
            return add('DGA domain anomaly',.88,'high',{'dns_length':len(dns),'dns_entropy':round(ent,2),'ngram_diversity':round(ng,2)})
        if tls.startswith(('RARE','JA4-C2')):
            return add('Encrypted-session metadata anomaly',.84,'medium',{'fingerprint':tls,'encrypted_payload_inspected':False})
        times=list(self.pair_times[key]); periodic=False
        if len(times)>=5:
            gaps=[times[i]-times[i-1] for i in range(1,len(times)) if times[i]>=times[i-1]]
            if len(gaps)>=4:
                mean=sum(gaps)/len(gaps); periodic=mean>0 and (max(gaps)-min(gaps))/mean<=.25
        if self.pair_count[key]>=5 and periodic and packets<=3 and outb<=800 and inb<=1200:
            return add('Possible C2 beaconing',.86,'medium',{'repeated_pair_count':self.pair_count[key],'interarrival_profile':'periodic','encrypted_payload_inspected':False})
        if self._ml:
            try:
                pred,prob=self._ml(f)
                mapping={'syn_flood':'SYN flood','beacon':'Possible C2 beaconing','dga':'DGA domain anomaly','dns_tunnel':'DNS tunnelling','tls_anomaly':'Encrypted-session metadata anomaly','scan':'Recon / port scan','data_exfiltration':'Possible data exfiltration','udp_amplification':'UDP amplification','benign':None}
                threat=mapping.get(pred)
                if threat and prob>=.78:
                    sev='critical' if threat in {'SYN flood','UDP amplification'} else 'high' if threat in {'Recon / port scan','Possible data exfiltration','DGA domain anomaly','DNS tunnelling'} else 'medium'
                    return add(threat,prob,sev,{'ml_class':pred,'ml_probability':round(prob,3),'model':'RandomForest','payload_decryption':False},'machine_learning')
            except Exception:
                pass
        return None
