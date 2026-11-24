# Hackathon compliance notes (Kiroween 2026)

Last checked 2026-11-24.

## Sources and access
Automated fetches of `https://kiroween.devpost.com/`, `/rules`, and `/details/faqs` from the development sandbox returned HTTP 403 every time (2026-11-24, several attempts). The facts below come from search-engine snippets of those pages and from a secondary write-up. **A participant must read the full rules page before submitting**; until then, every item marked "unverified" stays open.

## Confirmed from official-page snippets
- Projects must be built during the submission period, October 30 to December 4, 2026. Projects started earlier, including Kiroween 2025 projects, are not eligible ([kiroween.devpost.com](https://kiroween.devpost.com/)).
- The event lists Kiro Crew, specs, hooks, steering, powers, and MCP as ways to use Kiro, and $100,000 in prizes ([kiroween.devpost.com](https://kiroween.devpost.com/)).

## From secondary sources (unverified against the rules)
- The demo video must be under three minutes, and judges may stop at the three-minute mark ([dev.to write-up](https://dev.to/brian_mk/decoding-kiroween-4nm), 2025 event).
- Frankenstein category: combine seemingly incompatible technologies into one application ([Kiroween 2025 page](https://kiroween-2025.devpost.com/)).
- The 2026 event has bonus blog prizes and a "Best Kiro Crew App" entry type (participant posts found by search).

## This project against the known requirements
| Requirement | Status |
|---|---|
| Built in the submission period | This repository was created on 2026-11-24. Its first commit, `1d2fdeb`, is dated 2026-11-24. The earlier `leninathikam/necroshield` repository was deleted by its owner, and none of its code was used. |
| Public source and license | Public GitHub repository, MIT `LICENSE` at the root |
| Root `.kiro` directory | Committed: steering, specs, and hooks |
| Working application | Builds and passes CI. **Not yet hosted**; see `evidence/final-verification.md` |
| Demo video under 3 minutes | Script in `docs/demo-script.md`. **Not recorded**: the participant must record it |
| Category | Frankenstein, as the participant chose. The project joins a Python policy engine, the official MCP SDK, FastAPI, Next.js with React Flow, a standalone verifier, and an optional live-model loop |

## Bonus prizes
- **Kiro Crew:** not claimed. No Kiro Crew app exists in this project.
- **Blog prize:** not claimed; no post has been written.

## Open items for the participant
1. Read the full rules and FAQ, and confirm the video length, required fields, and any category restrictions.
2. Provide hosting access, or deploy with `render.yaml` or the `Dockerfile`, and keep the app online through judging.
3. Record the demo video from `docs/demo-script.md`.
4. Decide whether to configure a live model provider. Without one, the live track shows "unavailable".
