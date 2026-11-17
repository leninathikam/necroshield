"use client";

import { useMemo } from "react";
import {
  Background, BackgroundVariant, Controls, Handle, Position, ReactFlow,
  type Edge, type Node, type NodeProps,
} from "@xyflow/react";
import { ArrowUpRight, FileText, ShieldCheck, ShieldX, Zap } from "lucide-react";
import type { Pair, Run, TraceEvent } from "@/lib/types";

type EventData = { event: TraceEvent; mode: Run["mode"]; selected: boolean; label: string };
type EventNode = Node<EventData, "event">;

function EventCard({ data }: NodeProps<EventNode>) {
  const denied = data.event.decision === "deny";
  const Icon = denied ? ShieldX : data.event.decision === "allow" ? ShieldCheck : data.event.tool ? Zap : FileText;
  return <div className={`event-node ${denied ? "denied" : data.mode} ${data.selected ? "selected" : ""}`}>
    <Handle type="target" position={Position.Left} />
    <span className="node-eyebrow">{data.mode} / {String(data.event.sequence).padStart(2, "0")}</span>
    <div className="node-title"><Icon size={16} /><span>{data.label}</span></div>
    <div className="node-status"><i />{data.event.decision || data.event.kind.replaceAll("_", " ")}<ArrowUpRight size={11} /></div>
    <Handle type="source" position={Position.Right} />
  </div>;
}

const nodeTypes = { event: EventCard };

export function AttackGraph({ pair, selected, onSelect }: {
  pair: Pair | null;
  selected: { mode: Run["mode"]; sequence: number } | null;
  onSelect: (event: TraceEvent, mode: Run["mode"]) => void;
}) {
  const { nodes, edges } = useMemo(() => {
    const nodes: EventNode[] = [];
    const edges: Edge[] = [];
    if (!pair) return { nodes, edges };
    ([pair.baseline, pair.protected] as Run[]).forEach((run, lane) => {
      const decisions = run.events.filter(event => event.kind === "policy.decision");
      const visible = decisions.length ? decisions : run.events;
      visible.forEach((event, index) => {
        const id = `${run.mode}-${event.sequence}`;
        nodes.push({ id, type: "event", position: { x: index * 225, y: lane * 180 },
          data: { event, mode: run.mode, selected: selected?.mode === run.mode && selected?.sequence === event.sequence,
            label: event.tool || event.kind.replaceAll("_", " ") },
          ariaLabel: `${run.mode}, event ${event.sequence}, ${event.tool || event.kind}, ${event.decision || "trace"}`,
        });
        if (index > 0) edges.push({ id: `${run.mode}-edge-${index}`, source: `${run.mode}-${visible[index - 1].sequence}`, target: id,
          type: "smoothstep", style: { stroke: lane ? "#a58af5" : "#bb9458", strokeWidth: 1.6 },
          animated: false,
        });
      });
    });
    return { nodes, edges };
  }, [pair, selected]);

  if (!pair) return <div className="graph-empty">
    <div className="empty-orbit"><ShieldCheck size={32} strokeWidth={1.1} /></div>
    <p>The boundary is the experiment.</p>
    <span>Launch a scenario to trace the same intents<br />with and without policy enforcement.</span>
    <div className="empty-lanes"><span><i className="dot amber" />BASELINE</span><span className="lane-divider" /><span><i className="dot violet" />PROTECTED</span></div>
  </div>;

  return <div className="flow-container" aria-label="Counterfactual tool decision graph">
    <ReactFlow key={pair.id} nodes={nodes} edges={edges} nodeTypes={nodeTypes} fitView
      fitViewOptions={{ padding: 0.24, maxZoom: 1.1 }} minZoom={0.12} maxZoom={1.5}
      nodesDraggable={false} nodesConnectable={false} elementsSelectable
      onNodeClick={(_, node) => { const data = node.data as EventData; onSelect(data.event, data.mode); }}
      onNodeDoubleClick={(_, node) => { const data = node.data as EventData; onSelect(data.event, data.mode); }}
      proOptions={{ hideAttribution: false }}>
      <Background variant={BackgroundVariant.Dots} color="#3d3b47" gap={22} size={1} />
      <Controls showInteractive={false} />
    </ReactFlow>
  </div>;
}
