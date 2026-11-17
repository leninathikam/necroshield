"use client";

import { ArrowUpRight, Clock3 } from "lucide-react";
import type { Run, TraceEvent } from "@/lib/types";

export function Timeline({ run, onSelect, selected }: { run: Run; onSelect: (event: TraceEvent) => void; selected: number | undefined }) {
  return <div className="timeline-scroll"><ol className="timeline-list">{run.events.map(event => <li key={event.sequence}>
    <button className={`timeline-row ${selected === event.sequence ? "active" : ""}`} onClick={() => onSelect(event)}>
      <span className="timeline-sequence">{String(event.sequence).padStart(2, "0")}</span>
      <span className={`timeline-marker ${event.decision || "trace"}`} />
      <span className="timeline-main"><strong>{event.tool || event.kind.replaceAll("_", " ")}</strong><span>{event.message || event.reason}</span></span>
      <span className={`timeline-decision ${event.decision || "trace"}`}>{event.decision || event.kind}</span><ArrowUpRight size={14} />
    </button>
  </li>)}</ol><div className="timeline-end"><Clock3 size={12} />{run.events.length} recorded events · {run.id}</div></div>;
}
