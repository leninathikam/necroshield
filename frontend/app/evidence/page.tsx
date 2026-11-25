"use client";

import { useState } from "react";
import { RunPage } from "@/components/RunPage";
import { Timeline } from "@/components/Timeline";
import { api } from "@/lib/api";
import type { Mode, Verification } from "@/lib/types";

const MAX_UPLOAD = 256 * 1024;

function UploadVerifier() {
  const [result, setResult] = useState<Verification | null>(null);
  const [error, setError] = useState("");
  const [signed, setSigned] = useState<unknown>(null);
  const [key, setKey] = useState("");
  async function onFile(file: File | undefined) {
    setResult(null);
    setError("");
    setSigned(null);
    if (!file) return;
    if (file.size > MAX_UPLOAD) return setError("file is larger than 256 KB");
    try {
      const document: unknown = JSON.parse(await file.text());
      if (typeof document === "object" && document !== null && (document as { format?: string }).format === "necroshield.signed/1") {
        setSigned(document); // a signature is only meaningful against a key the user trusts
        return;
      }
      setResult(await api.verify(document));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }
  async function checkSigned() {
    setError("");
    try {
      setResult(await api.verifySigned(signed, key.trim()));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }
  return (
    <section className="panel" aria-labelledby="upload">
      <h2 id="upload" style={{ marginBottom: 8 }}>Verify an exported file</h2>
      <p className="dim" style={{ marginBottom: 12 }}>
        Checks a pair export, benchmark bundle, or live run with the same standalone verifier you can run offline:{" "}
        <code>python scripts/verify_evidence.py FILE</code>.
      </p>
      <input type="file" accept="application/json,.json" aria-label="Evidence file" onChange={(e) => onFile(e.target.files?.[0])} />
      {signed !== null && (
        <div className="stack" style={{ marginTop: 12 }}>
          <p className="dim">
            This file is signed. Paste the public key you trust (hex or base64), obtained from the publisher by a channel other
            than this file. A signature is never checked against a key taken from the file itself. This page asks this server to
            check it; for a check that does not rely on this server, run <code>python scripts/verify_evidence.py FILE --public-key KEY</code>.
          </p>
          <label>
            Trusted public key
            <input value={key} onChange={(e) => setKey(e.target.value)} aria-label="Trusted public key" spellCheck={false} />
          </label>
          <p><button className="btn btn-primary" onClick={checkSigned} disabled={key.trim().length < 44}>Check signature and evidence</button></p>
        </div>
      )}
      {error && <p role="alert" className="state-error" style={{ marginTop: 10 }}>{error}</p>}
      {result && (
        <div style={{ marginTop: 12 }} role="status">
          {result.verified ? (
            <span className="chip chip-verified">verified</span>
          ) : (
            <>
              <span className="chip chip-failed">rejected</span>
              <ul>{result.problems.map((p) => <li key={p} className="dim">{p}</li>)}</ul>
            </>
          )}
        </div>
      )}
    </section>
  );
}

export default function EvidencePage() {
  const [mode, setMode] = useState<Mode>("protected");
  return (
    <>
      <RunPage
        title="Evidence Explorer"
        intro="Every event is redacted, then hash-linked to the previous one. Select an event to inspect its decision, arguments, and hashes."
      >
        {(d) => {
          const run = d.export.runs.find((r) => r.mode === mode)!;
          return (
            <section className="panel">
              <div className="panel-title">
                <div className="row" role="group" aria-label="Run to inspect">
                  {(["baseline", "protected"] as const).map((m) => (
                    <button key={m} className="btn" aria-pressed={m === mode} onClick={() => setMode(m)}>
                      {m}
                    </button>
                  ))}
                </div>
                <span className="hash">head {run.head.slice(0, 20)}… · scenario digest {d.export.scenario.digest.slice(0, 12)}… · policy digest {d.export.policy.digest.slice(0, 12)}…</span>
              </div>
              <Timeline key={run.run_id} run={run} />
              <p className="faint" style={{ marginTop: 12 }}>
                Integrity limit: the chain detects edited, reordered, inserted, or removed events and decisions that contradict
                the exported policy. Exports are not signed, so a full consistent rewrite is caught only by pinning the
                scenario and policy digests from a trusted source.
              </p>
            </section>
          );
        }}
      </RunPage>
      <div style={{ marginTop: 16 }}>
        <UploadVerifier />
      </div>
    </>
  );
}
