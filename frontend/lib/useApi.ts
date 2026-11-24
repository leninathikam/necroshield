"use client";

import { useCallback, useEffect, useRef, useState } from "react";

export type Loadable<T> =
  | { state: "loading" }
  | { state: "error"; message: string }
  | { state: "ready"; data: T };

/** Loads data with an AbortController; a newer request always supersedes an older one,
 * so a slow stale response can never overwrite the current selection. */
export function useApi<T>(load: (signal: AbortSignal) => Promise<T>, deps: unknown[]) {
  const [value, setValue] = useState<Loadable<T>>({ state: "loading" });
  const generation = useRef(0);

  const reload = useCallback(() => {
    const mine = ++generation.current;
    const controller = new AbortController();
    setValue({ state: "loading" });
    load(controller.signal)
      .then((data) => mine === generation.current && setValue({ state: "ready", data }))
      .catch((error: unknown) => {
        if (controller.signal.aborted || mine !== generation.current) return;
        setValue({ state: "error", message: error instanceof Error ? error.message : String(error) });
      });
    return () => controller.abort();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  useEffect(() => reload(), [reload]);
  return [value, reload] as const;
}
