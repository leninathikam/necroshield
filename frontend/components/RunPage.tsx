"use client";

import { Suspense, type ReactNode } from "react";
import { api } from "@/lib/api";
import type { RunDetail, ScenarioView } from "@/lib/types";
import { useApi } from "@/lib/useApi";
import { PairPicker, useLatestPairId, usePairId } from "./PairPicker";
import { VerifiedChip } from "./Chips";
import { Empty, ErrorState, Load, Loading } from "./States";

type Render = (detail: RunDetail, scenario: ScenarioView | undefined) => ReactNode;

function Inner({ title, intro, children }: { title: string; intro: string; children: Render }) {
  const [explicit, setPair] = usePairId();
  const pairId = useLatestPairId(explicit);
  const [scenarios] = useApi((s) => api.scenarios(s), []);
  const [detail, reload] = useApi(
    (signal) => (pairId ? api.run(pairId, signal) : Promise.resolve(null)),
    [pairId],
  );
  return (
    <>
      <header className="page-head">
        <div>
          <h1>{title}</h1>
          <p>{intro}</p>
        </div>
        <PairPicker value={pairId} onChange={setPair} />
      </header>
      <Load value={detail} onRetry={reload}>
        {(d) => {
          if (!d) return <Empty>No run selected yet.</Empty>;
          const scenario = scenarios.state === "ready" ? scenarios.data.find((s) => s.id === d.export.scenario.id) : undefined;
          const stale = scenario && scenario.digest !== d.export.scenario.digest;
          return (
            <div className="stack">
              <div className="row">
                <VerifiedChip verified={d.verification.verified} />
                <span className="hash">pair {d.summary.pair_id}</span>
                <span className="faint">
                  {d.export.scenario.id}@{d.export.scenario.version} · {d.export.replay_mode} · policy {d.export.policy.version} (
                  {d.export.policy.source})
                </span>
                {stale && <span className="chip chip-denied">scenario definition changed since this run</span>}
              </div>
              {d.verification.verified ? (
                children(d, scenario)
              ) : (
                <ErrorState
                  prefix="Evidence failed verification, so no conclusions are shown"
                  message={d.verification.problems.join("; ")}
                />
              )}
            </div>
          );
        }}
      </Load>
    </>
  );
}

export function RunPage(props: { title: string; intro: string; children: Render }) {
  return (
    <Suspense fallback={<Loading />}>
      <Inner {...props} />
    </Suspense>
  );
}
