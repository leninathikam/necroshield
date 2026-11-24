"use client";

import { useState } from "react";
import type { ChainEvent, RunExport, ToolCallData } from "@/lib/types";
import { argsText, short } from "@/lib/events";
import { CallChip } from "./Chips";

function title(event: ChainEvent): string {
  if (event.kind === "tool_call") return (event.data as unknown as ToolCallData).tool;
  return event.kind === "run_started" ? "run started" : "run completed";
}

export function Timeline({ run }: { run: RunExport }) {
  const [selected, setSelected] = useState(0);
  const event = run.events[selected];
  return (
    <div className="grid-2">
      <ol className="timeline" aria-label={`${run.mode} event chain`}>
        {run.events.map((e, i) => (
          <li key={e.hash}>
            <button aria-pressed={i === selected} onClick={() => setSelected(i)}>
              <span className="seq">#{e.seq}</span>
              <span>
                {title(e)}
                {e.kind === "tool_call" && (
                  <span className="faint"> ({argsText((e.data as unknown as ToolCallData).bound_args)})</span>
                )}
              </span>
              {e.kind === "tool_call" ? <CallChip call={e.data as unknown as ToolCallData} /> : <span />}
            </button>
          </li>
        ))}
      </ol>
      {event && <EventInspector event={event} />}
    </div>
  );
}

export function EventInspector({ event }: { event: ChainEvent }) {
  return (
    <section className="inspector" aria-label={`event ${event.seq} details`}>
      <h3 style={{ marginBottom: 10 }}>
        Event #{event.seq}: {event.kind}
      </h3>
      <dl>
        <dt>run</dt>
        <dd className="hash">{event.run_id}</dd>
        <dt>prev hash</dt>
        <dd className="hash">{short(event.prev_hash, 24)}…</dd>
        <dt>hash</dt>
        <dd className="hash">{short(event.hash, 24)}…</dd>
        {Object.entries(event.data).map(([key, value]) => (
          <FragmentRow key={key} name={key} value={value} />
        ))}
      </dl>
    </section>
  );
}

function FragmentRow({ name, value }: { name: string; value: unknown }) {
  const text = typeof value === "string" ? value : JSON.stringify(value, null, 1);
  return (
    <>
      <dt>{name}</dt>
      <dd>
        <code style={{ whiteSpace: "pre-wrap" }}>{text}</code>
      </dd>
    </>
  );
}
