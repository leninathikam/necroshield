"use client";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { api } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import { Empty, Load } from "./States";

/** Chooses which stored pair a page shows. The choice lives in the URL (?pair=), so it survives
 * refreshes and can be shared. Without one, the newest run is used. */
export function usePairId(): [string | null, (id: string) => void] {
  const params = useSearchParams();
  const router = useRouter();
  const pair = params.get("pair");
  return [pair, (id: string) => router.replace(`?pair=${encodeURIComponent(id)}`)];
}

export function PairPicker({ value, onChange }: { value: string | null; onChange: (id: string) => void }) {
  const [runs, reload] = useApi((signal) => api.runs(50, signal), []);
  return (
    <Load value={runs} onRetry={reload}>
      {(list) =>
        list.length === 0 ? (
          <Empty>
            No runs yet. Launch one from the <Link href="/arena/">Attack Arena</Link>.
          </Empty>
        ) : (
          <label style={{ minWidth: 280 }}>
            Run
            <select
              value={value ?? list[0]!.pair_id}
              onChange={(e) => onChange(e.target.value)}
              aria-label="Select a stored run"
            >
              {value && !list.some((r) => r.pair_id === value) && (
                <option value={value}>selected run · {value.slice(0, 8)}</option>
              )}
              {list.map((r) => (
                <option key={r.pair_id} value={r.pair_id}>
                  {r.scenario_id} · {r.policy_source === "custom" ? "custom policy" : "default policy"} ·{" "}
                  {new Date(r.created_at).toLocaleTimeString()} · {r.pair_id.slice(0, 8)}
                </option>
              ))}
            </select>
          </label>
        )
      }
    </Load>
  );
}

export function useLatestPairId(explicit: string | null) {
  const [runs] = useApi((signal) => api.runs(1, signal), []);
  if (explicit) return explicit;
  return runs.state === "ready" ? (runs.data[0]?.pair_id ?? null) : null;
}
