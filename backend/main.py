from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .detector import PassiveDetector
from .models import Flow, IngestResponse, StartSimulation
from .simulator import FlowSimulator

BASE = Path(__file__).resolve().parent.parent
STATIC = BASE / "static"
RUNS = BASE / "runs"
RUNS.mkdir(exist_ok=True)

app = FastAPI(title="One-Way Passive Threat Detection V7")
app.mount("/static", StaticFiles(directory=STATIC), name="static")

detector = PassiveDetector()
simulator = FlowSimulator()
clients: set[WebSocket] = set()
active_task: asyncio.Task | None = None

state = {
    "running": False,
    "scenario": None,
    "rate": 0,
    "seconds": 0,
    "started_at": None,
    "flows": 0,
    "alerts": 0,
    "normal": 0,
    "latency_ms_sum": 0.0,
    "end_to_end_latency_ms_sum": 0.0,
    "source": None,
    "run_id": None,
    "run_path": None,
    "pcap": None,
}


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_run(kind: str):
    rid = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    path = RUNS / f"{kind}_{rid}"
    path.mkdir(parents=True, exist_ok=False)
    return rid, path


def reset_runtime():
    detector.reset()
    state.update(
        flows=0,
        alerts=0,
        normal=0,
        latency_ms_sum=0.0,
        end_to_end_latency_ms_sum=0.0,
        source=None,
        run_id=None,
        run_path=None,
        pcap=None,
    )


def write_event(path: Path, event: dict):
    with (path / "events.jsonl").open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(event, default=str) + "\n")


async def broadcast(event: dict):
    dead = []
    for ws in list(clients):
        try:
            await ws.send_json(event)
        except Exception:
            dead.append(ws)
    for ws in dead:
        clients.discard(ws)


def process_flow(flow: Flow, source: str, path: Path) -> dict:
    started = time.perf_counter()
    alert = detector.process(flow.model_dump())
    latency_ms = (time.perf_counter() - started) * 1000.0
    end_to_end_ms = latency_ms

    state["flows"] += 1
    state["latency_ms_sum"] += latency_ms
    state["end_to_end_latency_ms_sum"] += end_to_end_ms
    if alert:
        state["alerts"] += 1
    else:
        state["normal"] += 1

    event = {
        "type": "flow_result",
        "source": source,
        "flow": flow.model_dump(),
        "alert": alert,
        "normal": alert is None,
        "latency_ms": round(latency_ms, 3),
        "end_to_end_latency_ms": round(end_to_end_ms, 3),
        "processed_at": now(),
    }
    write_event(path, event)
    return event


def build_summary() -> dict:
    return {
        "flows": state["flows"],
        "normal_flows": state["normal"],
        "alert_count": state["alerts"],
        "average_latency_ms": round(state["latency_ms_sum"] / state["flows"], 3) if state["flows"] else 0.0,
        "average_end_to_end_latency_ms": round(state["end_to_end_latency_ms_sum"] / state["flows"], 3) if state["flows"] else 0.0,
        "threat_classes": dict(
            Counter(a["threat_class"] for a in detector.alert_history)
        ),
        "severity_counts": dict(Counter(a["severity"] for a in detector.alert_history)),
        "detection_methods": dict(Counter(a.get("evidence",{}).get("detection_method","unknown") for a in detector.alert_history)),
    }


async def finish_run(path: Path, run_type: str, extra: dict | None = None):
    summary = {
        **build_summary(),
        "run_type": run_type,
        "run_id": state["run_id"],
        "completed_at": now(),
        **(extra or {}),
    }
    (path / "summary.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8"
    )
    await broadcast({"type": "run_complete", "summary": summary})


async def simulation_loop(start: StartSimulation, path: Path):
    deadline = None if start.seconds == 0 else time.monotonic() + start.seconds
    try:
        while state["running"] and (deadline is None or time.monotonic() < deadline):
            flow = Flow.model_validate(simulator.next_flow(start.scenario))
            await broadcast(process_flow(flow, "built_in_simulator", path))
            await asyncio.sleep(1.0 / start.rate)
    except asyncio.CancelledError:
        raise
    finally:
        state["running"] = False
        await finish_run(path, "simulation")


@app.get("/")
async def index():
    return FileResponse(STATIC / "index.html")


@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "version": "7.0",
        "architecture": "hybrid_passive_ml",
        "ai_ml": True,
        "threat_intelligence": True,
        "flow_reconstruction": True,
        "read_only": True,
        "return_path": False,
        "payload_decryption": False,
    }


@app.get("/api/ml")
async def ml_info():
    try:
        report=json.loads((BASE/"evaluation"/"model_evaluation.json").read_text(encoding="utf-8"))
    except Exception: report={}
    return {"model":"RandomForest","trained":True,"feature_count":len(__import__("backend.features",fromlist=["FEATURE_NAMES"]).FEATURE_NAMES),"evaluation":report}

@app.get("/api/threat-intelligence")
async def threat_intelligence():
    from .threat_intel import load_iocs
    db=load_iocs(); return {"source":"local IOC feed","ips":len(db.get("ips",{})),"domains":len(db.get("domains",{})),"tls_fingerprints":len(db.get("tls_fingerprints",{}))}

@app.get("/api/scenarios")
async def scenarios():
    return {
        "scenarios": [
            "benign", "mixed", "syn_flood",
            "beacon", "dga", "dns_tunnel", "tls_anomaly", "scan", "data_exfiltration"
        ]
    }


@app.get("/api/state")
async def api_state():
    avg = state["latency_ms_sum"] / state["flows"] if state["flows"] else 0.0
    e2e = state["end_to_end_latency_ms_sum"] / state["flows"] if state["flows"] else 0.0
    return {**state, "average_latency_ms": round(avg, 3), "average_end_to_end_latency_ms": round(e2e, 3)}


@app.get("/api/runs")
async def list_runs():
    results = []
    for path in sorted(RUNS.iterdir(), reverse=True):
        if not path.is_dir():
            continue
        summary = {}
        summary_file = path / "summary.json"
        if summary_file.exists():
            try:
                summary = json.loads(summary_file.read_text(encoding="utf-8"))
            except Exception:
                summary = {}
        results.append({"name": path.name, "summary": summary})
    return {"runs": results[:100]}

@app.get("/api/runs/{run_id}/events")
async def run_events(run_id: str):
    safe = Path(run_id).name
    path = RUNS / safe
    events_file = path / "events.jsonl"
    summary_file = path / "summary.json"
    if not path.is_dir() or not events_file.exists():
        raise HTTPException(404, "Run not found")
    events = []
    with events_file.open("r", encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                events.append(json.loads(line))
    summary = json.loads(summary_file.read_text(encoding="utf-8")) if summary_file.exists() else {}
    return {"run_id": safe, "summary": summary, "events": events}


@app.post("/api/simulation/start")
async def start_simulation(start: StartSimulation):
    global active_task

    if state["running"]:
        raise HTTPException(409, "A run is already active")

    reset_runtime()
    rid, path = new_run("simulation")
    state.update(
        running=True,
        scenario=start.scenario,
        rate=start.rate,
        seconds=start.seconds,
        started_at=now(),
        source="built_in_simulator",
        run_id=rid,
        run_path=str(path),
    )
    active_task = asyncio.create_task(simulation_loop(start, path))
    return {
        "status": "started",
        "run_id": rid,
        "duration_mode": "continuous_until_stop" if start.seconds == 0 else "fixed_seconds",
        "seconds": start.seconds,
    }


@app.post("/api/simulation/stop")
async def stop_simulation():
    if not state["running"]:
        return {"status": "not_running"}
    state["running"] = False
    return {"status": "stopping"}


@app.post("/api/ingest", response_model=IngestResponse)
async def ingest(flow: Flow):
    if state["running"]:
        raise HTTPException(409, "Stop the active simulation before manual ingest")

    if not state["run_id"]:
        reset_runtime()
        rid, path = new_run("ingest")
        state.update(run_id=rid, run_path=str(path), source="api_ingest")
    else:
        path = Path(state["run_path"])

    event = process_flow(flow, "api_ingest", path)
    await broadcast(event)

    # Persist an updated summary after each manual ingest event.
    (path / "summary.json").write_text(
        json.dumps({
            **build_summary(),
            "run_type": "ingest",
            "run_id": state["run_id"],
            "updated_at": now(),
        }, indent=2),
        encoding="utf-8",
    )
    return {"alert": event["alert"], "flow_id": flow.flow_id}


def _supported_tshark_fields(tshark: str):
    wanted = [
        "frame.time_epoch","frame.number","ip.src","ip.dst","tcp.srcport","tcp.dstport","udp.srcport","udp.dstport",
        "_ws.col.Protocol","frame.len","tcp.flags","dns.qry.name","dns.qry.type","tls.handshake.ja3","tls.handshake.ja3s",
        "tls.handshake.ja4","quic.version","quic.sni","quic.stream.length"
    ]
    try:
        r=subprocess.run([tshark,"-G","fields"],capture_output=True,text=True,timeout=30,check=False)
        available={line.split("\t",1)[1] for line in r.stdout.splitlines() if "\t" in line}
        return [x for x in wanted if x in available]
    except Exception:
        return wanted[:16]

def _tshark_args(tshark: str):
    fields=_supported_tshark_fields(tshark)
    return ["-T","fields","-E","separator=\\t","-E","quote=d"] + sum((["-e",x] for x in fields),[]), fields

def _parse_packet(line: str, fields: list[str], count: int):
    cols=line.split("\t"); data={f:(cols[i].strip('"') if i<len(cols) else "") for i,f in enumerate(fields)}
    src,dst=data.get("ip.src",""),data.get("ip.dst","")
    if not src or not dst: return None
    try: ts=float(data.get("frame.time_epoch") or time.time())
    except ValueError: ts=time.time()
    try: length=int(float(data.get("frame.len") or 0))
    except ValueError: length=0
    proto=data.get("_ws.col.Protocol","").upper(); protocol="QUIC" if "QUIC" in proto else "TCP" if "TCP" in proto else "UDP" if "UDP" in proto else proto or "IP"
    flags=data.get("tcp.flags","").upper(); tcp_flags="SYN" if "SYN" in flags and "ACK" not in flags else flags
    def pi(*keys):
        for k in keys:
            try:
                if data.get(k): return int(data[k])
            except ValueError: pass
        return 0
    return {"timestamp":ts,"frame":data.get("frame.number") or str(count),"src":src,"dst":dst,"src_port":pi("tcp.srcport","udp.srcport"),"dst_port":pi("tcp.dstport","udp.dstport"),"protocol":protocol,"length":length,"tcp_flags":tcp_flags,"dns_name":data.get("dns.qry.name") or None,"dns_record_type":data.get("dns.qry.type") or None,"ja3":data.get("tls.handshake.ja3") or None,"ja3s":data.get("tls.handshake.ja3s") or None,"ja4":data.get("tls.handshake.ja4") or None,"quic_version":data.get("quic.version") or None,"quic_sni":data.get("quic.sni") or None}

def _reconstruct_flows(stdout: str, fields: list[str]):
    # Bidirectional 5-tuple reconstruction from the passive capture. No packets are sent.
    flows={}; order=[]
    for i,line in enumerate(stdout.splitlines()):
        p=_parse_packet(line,fields,i)
        if not p: continue
        a=(p['src'],p['src_port']); b=(p['dst'],p['dst_port']); key=tuple(sorted((a,b)))+(p['protocol'],)
        if key not in flows:
            flows[key]={'timestamp':p['timestamp'],'flow_id':'pcap-'+str(p['frame']),'src_ip':p['src'],'dst_ip':p['dst'],'src_port':p['src_port'],'dst_port':p['dst_port'],'protocol':p['protocol'],'packets':0,'out_bytes':0,'in_bytes':0,'duration_ms':0.0,'tcp_flags':p['tcp_flags'],'dns_name':p['dns_name'],'dns_record_type':p['dns_record_type'],'tls_fingerprint':p['ja4'] or p['ja3'] or p['ja3s'],'tls_ja3':p['ja3'],'tls_ja3s':p['ja3s'],'tls_ja4':p['ja4'],'quic_version':p['quic_version'],'quic_sni':p['quic_sni'],'_first':p['timestamp'],'_last':p['timestamp'],'_src':p['src']}
            order.append(key)
        f=flows[key]; f['packets']+=1; f['duration_ms']=max(0,(p['timestamp']-f['_first'])*1000); f['_last']=p['timestamp']; f['out_bytes']+=p['length'] if p['src']==f['_src'] else 0; f['in_bytes']+=p['length'] if p['src']!=f['_src'] else 0
        f['tcp_flags']=p['tcp_flags'] or f['tcp_flags']; f['dns_name']=p['dns_name'] or f['dns_name']; f['dns_record_type']=p['dns_record_type'] or f['dns_record_type']; f['tls_fingerprint']=p['ja4'] or p['ja3'] or p['ja3s'] or f['tls_fingerprint']; f['tls_ja3']=p['ja3'] or f.get('tls_ja3'); f['tls_ja3s']=p['ja3s'] or f.get('tls_ja3s'); f['tls_ja4']=p['ja4'] or f.get('tls_ja4'); f['quic_version']=p['quic_version'] or f.get('quic_version'); f['quic_sni']=p['quic_sni'] or f.get('quic_sni')
    for k in order:
        f=flows[k]; [f.pop(x,None) for x in ['_first','_last','_src']]; yield Flow.model_validate(f)


@app.post("/api/pcap")
async def analyze_pcap(file: UploadFile = File(...)):
    if state["running"]:
        raise HTTPException(409, "Stop the active simulation first")

    filename = Path(file.filename or "capture.pcap").name
    if Path(filename).suffix.lower() not in {".pcap", ".pcapng", ".cap"}:
        raise HTTPException(400, "Use a .pcap, .pcapng or .cap file")

    reset_runtime()
    rid, path = new_run("pcap")
    capture_path = path / filename
    capture_path.write_bytes(await file.read())

    state.update(
        run_id=rid,
        run_path=str(path),
        source="pcap",
        pcap=filename,
    )

    tshark = shutil.which("tshark")
    if not tshark:
        await finish_run(
            path,
            "pcap",
            {
                "pcap_file": filename,
                "packets_traversed": 0,
                "error": "TShark is not installed or is not on PATH",
            },
        )
        raise HTTPException(
            503,
            "PCAP was saved, but TShark is not installed/on PATH. "
            "Install Wireshark/TShark and ensure 'tshark --version' works."
        )

    try:
        tshark_args, tshark_fields = _tshark_args(tshark)
        result = subprocess.run(
            [tshark, *tshark_args, "-r", str(capture_path)],
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
        )
    except subprocess.TimeoutExpired:
        await finish_run(path, "pcap", {"pcap_file": filename, "error": "TShark timeout"})
        raise HTTPException(504, "TShark exceeded the 10-minute processing limit")

    if result.returncode != 0:
        await finish_run(
            path,
            "pcap",
            {"pcap_file": filename, "error": result.stderr[-2000:]},
        )
        raise HTTPException(400, result.stderr[-2000:] or "TShark could not read the file")

    packets_traversed=len(result.stdout.splitlines())
    count=0
    for flow in _reconstruct_flows(result.stdout,tshark_fields):
        event=process_flow(flow,"pcap",path); await broadcast(event); count+=1
    await finish_run(path,"pcap",{"pcap_file":filename,"packets_traversed":packets_traversed,"flows_reconstructed":count,"flow_reconstruction":"bidirectional_5_tuple"})
    return {"status":"complete","run_id":rid,"packets_traversed":packets_traversed,"flows_reconstructed":count,"summary":build_summary()}


@app.websocket("/ws")
async def websocket(ws: WebSocket):
    await ws.accept()
    clients.add(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        clients.discard(ws)
    except Exception:
        clients.discard(ws)
