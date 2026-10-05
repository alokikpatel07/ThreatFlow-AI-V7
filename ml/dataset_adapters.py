from __future__ import annotations
from pathlib import Path
import pandas as pd
import numpy as np
from backend.features import FEATURE_NAMES

LABEL_MAP={'benign':'benign','normal':'benign','benign traffic':'benign','background':'benign','attack':'attack','ddos':'syn_flood','dos hulk':'syn_flood','dos goldeneye':'syn_flood','dos slowloris':'syn_flood','dos slowhttptest':'syn_flood','ftp-patator':'syn_flood','ssh-patator':'syn_flood','portscan':'scan','port scan':'scan','infiltration':'data_exfiltration','bot':'beacon','botnet':'beacon','web attack':'dga'}

def _clean(s): return str(s).strip().lower()
def _label(v):
    x=_clean(v)
    return LABEL_MAP.get(x, 'benign' if any(k in x for k in ['normal','benign']) else x.replace(' ','_'))

def _num(df,*names):
    for n in names:
        if n in df.columns: return pd.to_numeric(df[n],errors='coerce').fillna(0)
    return pd.Series(np.zeros(len(df)),index=df.index)

def cic_to_features(df):
    out=pd.DataFrame(index=df.index)
    out['out_bytes']=_num(df,'Total Length of Fwd Packets','totlen_fwd_pkts','Total Fwd Bytes')
    out['in_bytes']=_num(df,'Total Length of Bwd Packets','totlen_bwd_pkts','Total Backward Bytes')
    out['packets']=_num(df,'Total Fwd Packets','spkts')+_num(df,'Total Backward Packets','dpkts')
    out['duration_ms']=_num(df,'Flow Duration','dur')/1000
    out['bytes_per_packet']=(out.out_bytes+out.in_bytes)/out.packets.replace(0,1)
    out['out_in_ratio']=np.minimum(out.out_bytes/out.in_bytes.replace(0,1),1000); out['in_out_ratio']=np.minimum(out.in_bytes/out.out_bytes.replace(0,1),1000)
    for c in FEATURE_NAMES:
        if c not in out: out[c]=0.0
    return out[FEATURE_NAMES]

def unsw_to_features(df):
    return cic_to_features(df)

def load_cic_csv(path):
    df=pd.read_csv(path); label_col=next((c for c in df.columns if _clean(c) in {'label','attack_cat','class','category'}),None)
    if not label_col: raise ValueError('CIC/IDS CSV needs Label, Class, Attack_cat or Category')
    return cic_to_features(df), df[label_col].map(_label)

def load_unsw_csv(path):
    df=pd.read_csv(path); label_col=next((c for c in df.columns if _clean(c) in {'label','attack_cat','class','category'}),None)
    if not label_col: raise ValueError('UNSW-NB15 CSV needs label or attack_cat')
    return unsw_to_features(df), df[label_col].map(_label)

def load_dgarchive(path):
    p=Path(path); rows=[]
    for line in p.read_text(encoding='utf-8',errors='ignore').splitlines():
        domain=line.strip().split(',')[0].strip()
        if domain and '.' in domain: rows.append((domain,'dga'))
    X=pd.DataFrame(0.0,index=range(len(rows)),columns=FEATURE_NAMES); X['dns_length']=[len(x[0]) for x in rows]; X['dns_entropy']=[_entropy(x[0].split('.')[0]) for x in rows]; X['ngram_diversity']=[_ngram(x[0].split('.')[0]) for x in rows]; X['has_dns']=1.0
    return X,np.array([y for _,y in rows])

def _entropy(s):
    from backend.features import entropy; return entropy(s)
def _ngram(s):
    from backend.features import ngram_diversity; return ngram_diversity(s)
