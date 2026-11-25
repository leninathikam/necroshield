"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const LINKS = [
  ["/", "Dashboard"],
  ["/theatre/", "Attack Theatre"],
  ["/lab/", "Policy Lab"],
  ["/arena/", "Attack Arena"],
  ["/graph/", "Execution Graph"],
  ["/replay/", "Replay Lab"],
  ["/policy/", "Policy Inspector"],
  ["/evidence/", "Evidence Explorer"],
  ["/benchmark/", "Benchmark Studio"],
] as const;

export function Nav() {
  const path = usePathname();
  const current = (href: string) => (href === "/" ? path === "/" : path.startsWith(href.replace(/\/$/, "")));
  return (
    <nav className="nav" aria-label="Main">
      {LINKS.map(([href, label]) => (
        <Link key={href} href={href} aria-current={current(href) ? "page" : undefined}>
          {label}
        </Link>
      ))}
    </nav>
  );
}
