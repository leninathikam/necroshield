"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useEffect, useState } from "react";
import { Load, Loading } from "@/components/States";
import { api } from "@/lib/api";
import type { Grant, PolicyDoc, ScenarioView } from "@/lib/types";
import { useApi } from "@/lib/useApi";

const TOOLS: Record<string, string[]> = {
  read_document: ["path"],
  get_customer_record: ["customer_id"],
  write_report: ["report_id", "body"],
  send_message: ["to", "body", "attach"],
  read_memory: ["key"],
  write_memory: ["key", "value"],
};

interface Draft {
  enabled: boolean;
  grant: Grant;
}

const toText = (v: string[] | null) => (v === null ? "*" : v.join(", "));
const fromText = (t: string): string[] | null => (t.trim() === "*" ? null : t.split(",").map((s) => s.trim()).filter(Boolean));

function GrantEditor({ draft, onChange }: { draft: Draft; onChange: (d: Draft) => void }) {
  const { grant } = draft;
  return (
    <fieldset className="panel" style={{ margin: 0 }}>
      <legend className="row">
        <label style={{ flexDirection: "row", alignItems: "center" }}>
          <input type="checkbox" checked={draft.enabled} onChange={(e) => onChange({ ...draft, enabled: e.target.checked })} />
          <code>{grant.grant_id}</code>
        </label>
        <span className="chip">{grant.tool}</span>
      </legend>
      <div className="stack" style={{ gap: 10 }}>
        {Object.entries(grant.allowed_args).map(([arg, values]) => (
          <label key={arg}>
            {arg} <span className="faint">(comma-separated allowed values, or * for any string)</span>
            <input
              value={toText(values)}
              disabled={!draft.enabled}
              onChange={(e) =>
                onChange({ ...draft, grant: { ...grant, allowed_args: { ...grant.allowed_args, [arg]: fromText(e.target.value) } } })
              }
            />
          </label>
        ))}
      </div>
    </fieldset>
  );
}

function Editor({ scenario }: { scenario: ScenarioView }) {
  const router = useRouter();
  const [drafts, setDrafts] = useState<Draft[]>([]);
  const [newTool, setNewTool] = useState("send_message");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    setDrafts(scenario.policy.grants.map((g) => ({ enabled: true, grant: structuredClone(g) })));
    setError("");
  }, [scenario]);

  const policy: PolicyDoc = {
    version: "custom/1.0.0",
    grants: drafts.filter((d) => d.enabled).map((d) => d.grant),
  };

  function addGrant() {
    const id = `g-custom-${drafts.length + 1}`;
    const args = Object.fromEntries((TOOLS[newTool] ?? []).map((a) => [a, null])) as Record<string, string[] | null>;
    setDrafts([...drafts, { enabled: true, grant: { grant_id: id, tool: newTool, allowed_args: args } }]);
  }

  async function run(useDefault: boolean) {
    setBusy(true);
    setError("");
    try {
      const result = await api.startRun(scenario.id, useDefault ? undefined : policy);
      router.push(`/replay/?pair=${result.summary.pair_id}`);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setBusy(false);
    }
  }

  return (
    <div className="grid-2">
      <div className="stack">
        {drafts.map((d, i) => (
          <GrantEditor key={d.grant.grant_id} draft={d} onChange={(next) => setDrafts(drafts.map((x, j) => (j === i ? next : x)))} />
        ))}
        <div className="panel row">
          <label>
            New grant for
            <select value={newTool} onChange={(e) => setNewTool(e.target.value)}>
              {Object.keys(TOOLS).map((t) => <option key={t}>{t}</option>)}
            </select>
          </label>
          <button className="btn" onClick={addGrant}>Add grant</button>
        </div>
      </div>
      <div className="stack">
        <section className="panel">
          <h2 style={{ marginBottom: 8 }}>Policy to run</h2>
          <p className="faint" style={{ marginBottom: 10 }}>
            Default deny: any call not covered exactly by an enabled grant is refused before the tool runs. Edited policies
            are recorded as <code>custom</code> in the evidence.
          </p>
          <pre className="source" aria-label="Policy JSON">{JSON.stringify(policy, null, 2)}</pre>
          <div className="row" style={{ marginTop: 12 }}>
            <button className="btn btn-primary" onClick={() => run(false)} disabled={busy}>
              {busy ? "Running…" : "Run with this policy"}
            </button>
            <button className="btn" onClick={() => run(true)} disabled={busy}>Run with the default policy</button>
          </div>
          {error && <p role="alert" className="state state-error" style={{ marginTop: 12 }}>Rejected: {error}</p>}
        </section>
      </div>
    </div>
  );
}

function Inner() {
  const params = useSearchParams();
  const router = useRouter();
  const [scenarios, reload] = useApi((s) => api.scenarios(s), []);
  return (
    <>
      <header className="page-head">
        <div>
          <h1>Policy Inspector</h1>
          <p>Examine a scenario&apos;s grants, change them, and run the counterfactual. Synthetic scenarios only.</p>
        </div>
      </header>
      <Load value={scenarios} onRetry={reload}>
        {(list) => {
          const id = params.get("scenario") ?? list[0]!.id;
          const scenario = list.find((s) => s.id === id) ?? list[0]!;
          return (
            <div className="stack">
              <label style={{ maxWidth: 360 }}>
                Scenario
                <select value={scenario.id} onChange={(e) => router.replace(`?scenario=${e.target.value}`)}>
                  {list.map((s) => <option key={s.id} value={s.id}>{s.title}</option>)}
                </select>
              </label>
              <Editor scenario={scenario} />
            </div>
          );
        }}
      </Load>
    </>
  );
}

export default function PolicyPage() {
  return (
    <Suspense fallback={<Loading />}>
      <Inner />
    </Suspense>
  );
}
