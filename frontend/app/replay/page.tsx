"use client";

import Link from "next/link";
import { Attributions, RunCompare } from "@/components/RunCompare";
import { RunPage } from "@/components/RunPage";
import { api } from "@/lib/api";

export default function ReplayPage() {
  return (
    <RunPage
      title="Replay Lab"
      intro="Baseline and protected runs side by side. Both received the same intended calls; highlighted rows are where the policy decision differs."
    >
      {(d) => (
        <>
          <RunCompare pair={d.export} />
          <section className="panel">
            <div className="panel-title">
              <h2>Which decision changed the result</h2>
              <span className="faint">exact single-decision counterfactual over the deterministic fixture</span>
            </div>
            <Attributions analysis={d.analysis} />
          </section>
          <div className="row">
            <a className="btn" href={api.exportUrl(d.summary.pair_id)} download>
              Download evidence (JSON)
            </a>
            <Link className="btn" href={`/policy/?scenario=${d.export.scenario.id}`}>Modify the policy and re-run</Link>
            <Link className="btn" href={`/evidence/?pair=${d.summary.pair_id}`}>Inspect the event chain</Link>
          </div>
        </>
      )}
    </RunPage>
  );
}
