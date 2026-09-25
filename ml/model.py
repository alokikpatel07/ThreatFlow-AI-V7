from __future__ import annotations
from pathlib import Path
import json
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, confusion_matrix
from sklearn.model_selection import train_test_split
from backend.features import FEATURE_NAMES, extract_features
from backend.simulator import FlowSimulator, SCENARIOS

ROOT=Path(__file__).resolve().parent.parent
MODEL_PATH=ROOT/'models'/'threat_model.joblib'
REPORT_PATH=ROOT/'evaluation'/'model_evaluation.json'
LABELS=['benign','syn_flood','beacon','dga','dns_tunnel','tls_anomaly','scan','data_exfiltration','udp_amplification']

def labeled_samples(n_each=500):
    sim=FlowSimulator(); X=[]; y=[]
    for label in LABELS:
        for _ in range(n_each):
            if label=='udp_amplification':
                f={'flow_id':'train','src_ip':'10.0.0.1','dst_ip':'10.0.0.2','protocol':'UDP','packets':8,'out_bytes':100,'in_bytes':6000,'dst_port':53}
            else:
                f=sim.next_flow(label)
            X.append([extract_features(f)[k] for k in FEATURE_NAMES]); y.append(label)
    return np.asarray(X,dtype=float), np.asarray(y)

def train_and_evaluate():
    X,y=labeled_samples()
    Xtr,Xte,ytr,yte=train_test_split(X,y,test_size=.25,random_state=42,stratify=y)
    model=RandomForestClassifier(n_estimators=180,random_state=42,n_jobs=-1,class_weight='balanced_subsample')
    model.fit(Xtr,ytr); pred=model.predict(Xte)
    p,r,f,_=precision_recall_fscore_support(yte,pred,average='weighted',zero_division=0)
    report={'accuracy':float(accuracy_score(yte,pred)),'precision_weighted':float(p),'recall_weighted':float(r),'f1_weighted':float(f),'labels':LABELS,'confusion_matrix':confusion_matrix(yte,pred,labels=LABELS).tolist(),'validation_samples':int(len(yte))}
    MODEL_PATH.parent.mkdir(exist_ok=True); joblib.dump({'model':model,'features':FEATURE_NAMES,'labels':LABELS},MODEL_PATH)
    REPORT_PATH.parent.mkdir(exist_ok=True); REPORT_PATH.write_text(json.dumps(report,indent=2),encoding='utf-8')
    return model,report

def load_model():
    if not MODEL_PATH.exists(): return train_and_evaluate()[0]
    return joblib.load(MODEL_PATH)['model']

MODEL=load_model()

def predict_flow(f:dict):
    vals=np.asarray([[extract_features(f)[k] for k in FEATURE_NAMES]],dtype=float)
    probs=MODEL.predict_proba(vals)[0]; idx=int(np.argmax(probs)); classes=list(MODEL.classes_)
    return str(classes[idx]), float(probs[idx])
