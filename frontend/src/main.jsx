import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import "./style.css";

const names = { benign: "Normal / Benign", mixed: "Mixed traffic", syn_flood: "SYN flood", beacon: "Botnet beaconing", dga: "DGA domains", dns_tunnel: "DNS tunnelling", tls_anomaly: "TLS/QUIC metadata anomaly", scan: "Recon / port scan", data_exfiltration: "Data exfiltration" };

function App() {
    const [scenarios, setScenarios] = useState([]), [scenario, setScenario] = useState("mixed"), [rate, setRate] = useState(20), [seconds, setSeconds] = useState(0);
    const [state, setState] = useState({ detector_flows: 0, detector_alerts: 0, running: false }), [alerts, setAlerts] = useState([]);
    useEffect(() => { fetch("/api/scenarios").then(r => r.json()).then(x => setScenarios(x.scenarios)); const ws = new WebSocket((location.protocol === "https:" ? "wss://" : "ws://") + location.host + "/ws"); ws.onmessage = e => { const m = JSON.parse(e.data); if (m.state) setState(m.state); if (m.alert) setAlerts(a => [m.alert, ...a].slice(0, 100)) }; return () => ws.close() }, []);
    const start = () => fetch("/api/simulation/start", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ scenario, rate, seconds }) });
    const stop = () => fetch("/api/simulation/stop", { method: "POST" });
    return <div className="app"><header><div><h1>Passive Threat Detection SOC</h1><p>Live one-directional telemetry analytics</p></div><div className="badges"><span>READ ONLY</span><span>NO RETURN PATH</span><span>NO DECRYPTION</span></div></header>
        <section className="stats"><Card n={state.detector_flows || 0} l="Flows processed" /><Card n={state.detector_alerts || 0} l="Threat alerts" /><Card n={state.running ? "LIVE" : "IDLE"} l="Simulation" /></section>
        <main><aside><h2>Simulation</h2><label>Profile<select value={scenario} onChange={e => setScenario(e.target.value)}>{scenarios.map(x => <option key={x} value={x}>{names[x] || x}</option>)}</select></label><label>Flows/sec<input type="number" value={rate} onChange={e => setRate(+e.target.value)} /></label><label>Seconds (0 = until Stop)<input type="number" value={seconds} onChange={e => setSeconds(+e.target.value)} /></label><button onClick={start}>Start live simulation</button><button className="stop" onClick={stop}>Stop</button></aside>
            <section><h2>Threat alerts</h2>{alerts.length === 0 ? <div className="empty">No threat alerts. Benign traffic is telemetry only.</div> : alerts.map(a => <article key={a.flow_id}><b>{a.threat_class}</b><span>{a.severity} · {Math.round(a.confidence * 100)}%</span><small>{a.src_ip} → {a.dst_ip}</small><p>{JSON.stringify(a.evidence)}</p></article>)}</section></main></div>
}
function Card({ n, l }) { return <div className="card"><strong>{n}</strong><small>{l}</small></div> }
createRoot(document.getElementById("root")).render(<App />);
