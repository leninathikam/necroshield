"use client";

import "@xyflow/react/dist/style.css";
import { Background, Controls, MarkerType, ReactFlow, type Edge, type Node } from "@xyflow/react";
import { useEffect, useMemo, useState } from "react";
import { callState, toolCalls } from "@/lib/events";
import type { Check, RunExport } from "@/lib/types";

const PRODUCERS: Record<string, string[]> = {
  sink_contains: ["send_message"],
  resource_read: ["read_document", "get_customer_record", "read_memory"],
  memory_equals: ["write_memory"],
  report_equals: ["write_report"],
};
const COLORS = { allowed: "#a78bfa", denied: "#f5b14c", failed: "#f26d6d" } as const;

function usePrefersReducedMotion() {
  const [reduced, setReduced] = useState(false);
  useEffect(() => {
    const query = window.matchMedia("(prefers-reduced-motion: reduce)");
    setReduced(query.matches);
    const update = () => setReduced(query.matches);
    query.addEventListener("change", update);
    return () => query.removeEventListener("change", update);
  }, []);
  return reduced;
}

function box(label: string, detail: string, kind: string) {
  return {
    label: (
      <div className={`flow-node kind-${kind}`}>
        <strong>{label}</strong>
        <span className="dim">{detail}</span>
      </div>
    ),
  };
}

function buildGraph(run: RunExport, checks: { attack: Check[]; task: Check[] }, surface: string, step: number) {
  const calls = toolCalls(run);
  const tools = [...new Set(calls.map((c) => c.tool))];
  const protectedRun = run.mode === "protected";
  const nodes: Node[] = [
    { id: "source", position: { x: 0, y: 0 }, data: box("Attacker-controlled input", surface, "source"), type: "default" },
    { id: "agent", position: { x: 0, y: 200 }, data: box("Fixture agent", "plans from tool output", "agent") },
    {
      id: "gateway",
      position: { x: 290, y: 200 },
      data: box("Policy gateway", protectedRun ? "default-deny, before dispatch" : "baseline: no enforcement", "gateway"),
    },
    ...tools.map((tool, i) => ({
      id: `tool:${tool}`,
      position: { x: 590, y: i * 92 + (200 - ((tools.length - 1) * 92) / 2) },
      data: box(tool, "synthetic MCP tool", "tool"),
    })),
  ];
  const edges: Edge[] = [
    { id: "source-agent", source: "source", target: "agent", label: "read", style: { stroke: "#f26d6d" } },
  ];
  const visible = calls.slice(0, step);
  for (const tool of tools) {
    const mine = visible.filter((c) => c.tool === tool);
    if (mine.length === 0) continue;
    for (const state of ["allowed", "denied", "failed"] as const) {
      const count = mine.filter((c) => callState(c) === state).length;
      if (count === 0) continue;
      const color = COLORS[state];
      edges.push({
        id: `gw-${tool}-${state}`,
        source: "gateway",
        target: `tool:${tool}`,
        label: `${state === "allowed" ? "executed" : state} ×${count}`,
        animated: state === "allowed",
        style: { stroke: color, strokeDasharray: state === "denied" ? "6 4" : undefined, strokeWidth: 2 },
        labelStyle: { fill: color, fontSize: 11 },
        labelBgStyle: { fill: "#0b0b0d" },
        markerEnd: { type: MarkerType.ArrowClosed, color },
      });
    }
  }
  if (visible.length > 0) {
    edges.push({ id: "agent-gw", source: "agent", target: "gateway", label: `${visible.length} call(s)`, animated: true });
  }
  if (step >= calls.length) {
    const effects = run.outcome.observed_effects;
    const all = [...checks.attack.map((c) => ({ c, bad: true })), ...checks.task.map((c) => ({ c, bad: false }))];
    const observed = all.filter(({ c, bad }) => effects.includes(`${bad ? "attack" : "task"}: ${c.description}`));
    const shown = observed.length > 0 ? observed : [];
    shown.forEach(({ c, bad }, i) => {
      const id = `effect:${i}`;
      nodes.push({
        id,
        position: { x: 880, y: i * 92 + 60 },
        data: box(bad ? "Attack effect observed" : "Task effect observed", c.description, bad ? "effect-bad" : "effect-good"),
      });
      const producer = (PRODUCERS[c.kind] ?? []).find((t) => tools.includes(t));
      if (producer) {
        edges.push({
          id: `eff-${i}`,
          source: `tool:${producer}`,
          target: id,
          style: { stroke: bad ? "#f26d6d" : "#6fcf97" },
          markerEnd: { type: MarkerType.ArrowClosed, color: bad ? "#f26d6d" : "#6fcf97" },
        });
      }
    });
    if (!run.outcome.attack_succeeded && checks.attack.length > 0) {
      nodes.push({
        id: "effect:none",
        position: { x: 880, y: shown.length * 92 + 60 },
        data: box("No attack effect", "no attack check held after the run", "effect-good"),
      });
    }
  }
  return { nodes, edges, total: calls.length };
}

export function AttackGraph({
  run,
  checks,
  surface,
}: {
  run: RunExport;
  checks: { attack: Check[]; task: Check[] };
  surface: string;
}) {
  const reduced = usePrefersReducedMotion();
  const total = toolCalls(run).length;
  const [step, setStep] = useState(0);
  const [playing, setPlaying] = useState(true);

  useEffect(() => {
    setStep(reduced ? total : 0);
    setPlaying(!reduced);
  }, [run.run_id, reduced, total]);

  useEffect(() => {
    if (!playing || step >= total) return;
    const timer = window.setTimeout(() => setStep((s) => s + 1), 700);
    return () => window.clearTimeout(timer);
  }, [playing, step, total]);

  const graph = useMemo(() => buildGraph(run, checks, surface, step), [run, checks, surface, step]);
  const current = toolCalls(run)[step - 1];

  return (
    <div className="stack">
      <div className="row" role="group" aria-label="Graph playback">
        <button className="btn" onClick={() => setPlaying((p) => !p)} disabled={step >= total}>
          {playing && step < total ? "Pause" : "Play"}
        </button>
        <button className="btn" onClick={() => setStep((s) => Math.max(0, s - 1))} disabled={step === 0}>
          Step back
        </button>
        <button className="btn" onClick={() => setStep((s) => Math.min(total, s + 1))} disabled={step >= total}>
          Step forward
        </button>
        <button className="btn" onClick={() => { setStep(0); setPlaying(true); }}>
          Replay
        </button>
        <span className="faint" aria-live="polite">
          Event {step} of {total}
          {current ? `: ${current.tool} ${callState(current)}` : ""}
        </span>
      </div>
      <div className="graph" aria-label={`Execution graph for the ${run.mode} run`} role="img">
        <ReactFlow
          nodes={graph.nodes}
          edges={graph.edges}
          fitView
          nodesDraggable={false}
          nodesConnectable={false}
          proOptions={{ hideAttribution: true }}
          colorMode="dark"
        >
          <Background color="#24242c" gap={22} />
          <Controls showInteractive={false} />
        </ReactFlow>
      </div>
    </div>
  );
}
