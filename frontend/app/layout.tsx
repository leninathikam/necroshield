import type { Metadata } from "next";
import Link from "next/link";
import type { ReactNode } from "react";
import { Nav } from "@/components/Nav";
import "./globals.css";

export const metadata: Metadata = {
  title: "NecroShield",
  description: "Adversarial security testing for AI agent and MCP tool workflows, on synthetic data.",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>
        <a className="skip" href="#main">
          Skip to content
        </a>
        <div className="shell">
          <aside className="sidebar">
            <Link className="brand" href="/">
              <span className="brand-mark" aria-hidden>
                N
              </span>
              <strong>NecroShield</strong>
            </Link>
            <Nav />
            <p className="sidebar-note">
              Synthetic data only. Pair results come from runs on this server and are re-verified with the standalone
              verifier before they are shown. MCP transcripts and live runs are labeled separately.
            </p>
          </aside>
          <main id="main" className="main">
            {children}
          </main>
        </div>
      </body>
    </html>
  );
}
