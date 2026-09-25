from __future__ import annotations
import argparse, json
from pathlib import Path
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, confusion_matrix
from sklearn.model_selection import train_test_split
from ml.model import train_and_evaluate, MODEL_PATH, REPORT_PATH, LABELS
from ml.dataset_adapters import load_cic_csv, load_unsw_csv, load_dgarchive

def train_external(X,y,source):
    keep=np.isin(y,LABELS); X=X.loc[keep] if hasattr(X,'loc') else X[keep]; y=np.asarray(y)[keep]
    if len(set(y))<2: raise ValueError('Dataset must contain at least two supported classes after mapping')
    Xtr,Xte,ytr,yte=train_test_split(X,y,test_size=.25,random_state=42,stratify=y)
    model=RandomForestClassifier(n_estimators=220,random_state=42,n_jobs=-1,class_weight='balanced_subsample'); model.fit(Xtr,ytr); pred=model.predict(Xte)
    p,r,f,_=precision_recall_fscore_support(yte,pred,average='weighted',zero_division=0)
    report={'source':source,'accuracy':float(accuracy_score(yte,pred)),'precision_weighted':float(p),'recall_weighted':float(r),'f1_weighted':float(f),'labels':sorted(set(y)),'validation_samples':int(len(yte)),'confusion_matrix':confusion_matrix(yte,pred,labels=sorted(set(y))).tolist()}
    import joblib; joblib.dump({'model':model,'features':list(X.columns),'labels':sorted(set(y))},MODEL_PATH); REPORT_PATH.write_text(json.dumps(report,indent=2),encoding='utf-8'); print(json.dumps(report,indent=2)); return report

if __name__=='__main__':
    p=argparse.ArgumentParser(description='ThreatFlow AI V7 model trainer'); p.add_argument('--csv'); p.add_argument('--dataset',choices=['cic','unsw','dgarchive']); p.add_argument('--path'); a=p.parse_args()
    if not a.path: train_and_evaluate()
    elif a.dataset=='cic': train_external(*load_cic_csv(a.path),'CIC-IDS2017/CSE-CIC-IDS2018')
    elif a.dataset=='unsw': train_external(*load_unsw_csv(a.path),'UNSW-NB15')
    else: train_external(*load_dgarchive(a.path),'DGArchive')
