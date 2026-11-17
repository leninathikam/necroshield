import type { Metadata } from "next";
import "@xyflow/react/dist/style.css";
import "./globals.css";

export const metadata: Metadata = {
  title: "NecroShield — Agent security arena",
  description: "Reproduce the attack. Inspect the boundary. Verify the evidence. A synthetic security arena for agent tool workflows.",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body>{children}</body></html>;
}
