"use client";

import { Check, Copy, Fingerprint, ScanLine } from "lucide-react";
import { useState } from "react";
import type { Run, TraceEvent } from "@/lib/types";

export function Inspector({ event, mode }: { event: TraceEvent | null; mode: Run["mode"] }) {
  const [copied, setCopied] = useState(false);
  return <section className="panel inspector">
    <div className="panel-header"><h2><ScanLine size={16} />Decision inspector</h2><span className="mono muted">{event ? `#${String(event.sequence).padStart(2, "0")}` : "—"}</span></div>
    {!event ? <div className="inspector-empty"><ScanLine size={27} strokeWidth={1} /><p>Follow the evidence.</p><span>Select a graph node or timeline event to inspect the policy decision and its tool arguments.</span></div> : <div className="inspector-content">
      <div className="inspector-label"><span className="eyebrow">{mode} execution</span><span className={`decision ${event.decision || "trace"}`}>{event.decision || event.kind}</span></div>
      <h3>{event.tool || event.kind.replaceAll("_", " ")}</h3>
      <p className="reason">{event.reason || event.message}</p>
      {event.reason && event.message && event.reason !== event.message && <p className="event-message">{event.message}</p>}
      <div className="detail-block"><span className="eyebrow">Tool arguments</span><pre>{JSON.stringify(event.arguments, null, 2)}</pre></div>
      <div className="detail-block"><span className="eyebrow">Observed result</span><pre>{JSON.stringify(event.result, null, 2)}</pre></div>
      <div className="hash-block"><span><Fingerprint size={14} />Event SHA-256</span><button className="icon-button" aria-label="Copy event hash" title="Copy event hash" onClick={async () => {
        try { await navigator.clipboard.writeText(event.hash); setCopied(true); setTimeout(() => setCopied(false), 1800); } catch { setCopied(false); }
      }}>{copied ? <Check size={13} /> : <Copy size={13} />}</button><code>{event.hash}</code></div>
    </div>}
  </section>;
}
