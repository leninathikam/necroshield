import type {
  Benchmark,
  LiveResult,
  LiveStatus,
  McpReplay,
  Mode,
  PolicyDoc,
  RunDetail,
  RunSummary,
  ScenarioView,
  ToolSpecView,
  Verification,
} from "./types";

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

async function request<T>(path: string, init?: RequestInit & { signal?: AbortSignal }): Promise<T> {
  const response = await fetch(path, {
    ...init,
    headers: { "content-type": "application/json", ...(init?.headers ?? {}) },
  });
  if (!response.ok) {
    let detail = response.statusText;
    try {
      const body = (await response.json()) as { detail?: unknown };
      detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(response.status, detail);
  }
  return (await response.json()) as T;
}

const post = <T>(path: string, body: unknown, signal?: AbortSignal) =>
  request<T>(path, { method: "POST", body: JSON.stringify(body), signal });

export const api = {
  scenarios: (signal?: AbortSignal) => request<ScenarioView[]>("/api/scenarios", { signal }),
  runs: (limit = 25, signal?: AbortSignal) => request<RunSummary[]>(`/api/runs?limit=${limit}`, { signal }),
  run: (pairId: string, signal?: AbortSignal) => request<RunDetail>(`/api/runs/${encodeURIComponent(pairId)}`, { signal }),
  startRun: (scenarioId: string, policy?: PolicyDoc) =>
    post<RunDetail>("/api/runs", policy ? { scenario_id: scenarioId, policy } : { scenario_id: scenarioId }),
  verify: (document: unknown) => post<Verification>("/api/verify", document),
  benchmark: (signal?: AbortSignal) => request<Benchmark>("/api/benchmark", { signal }),
  runBenchmark: () => post<Benchmark>("/api/benchmark", {}),
  mcpReplay: (scenarioId: string, mode: Mode) => post<McpReplay>("/api/mcp/replay", { scenario_id: scenarioId, mode }),
  liveStatus: (signal?: AbortSignal) => request<LiveStatus>("/api/live/status", { signal }),
  liveRun: (scenarioId: string, mode: Mode, repetitions: number) =>
    post<LiveResult>("/api/live/runs", { scenario_id: scenarioId, mode, repetitions }),
  tools: (signal?: AbortSignal) => request<ToolSpecView[]>("/api/tools", { signal }),
  exportUrl: (pairId: string) => `/api/runs/${encodeURIComponent(pairId)}/export`,
  bundleUrl: "/api/benchmark/bundle",
};
