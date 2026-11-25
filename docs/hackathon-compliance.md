# Hackathon compliance (Kiroween 2026)

Last updated 2026-11-24. Category: **Frankenstein**.

## Source of the requirements
The official rules page (`https://kiroween.devpost.com/rules`, updated November 16, 2026, per the participant) returned HTTP 403 to every automated fetch from the development sandbox, including on 2026-11-24. The requirements below come from two sources, marked in the table:
- **[P]**: provided by the participant from the official rules page.
- **[S]**: confirmed by a search-engine snippet of `kiroween.devpost.com`.

Before submitting, the participant should re-read the rules page and confirm each row.

| Requirement | Source | Project status |
|---|---|---|
| Built during the submission period, October 30 to December 4, 2026; projects started earlier are ineligible | [S] | Met. The repository's first commit is dated 2026-11-24. The earlier repository of the same name was deleted, and none of its code was used. |
| Submission deadline: December 4, 2026, 2:00 PM Pacific | [P] | Open: the participant submits. |
| Publicly accessible application for judging | [P] | **Not met yet.** The blueprint and image are ready and CI-tested; there is no public URL (see `docs/deployment.md`). |
| Application stays accessible through judging, which ends **January 29, 2027** | [P] | **Not met yet.** Hosting is needed through that date; on the free plan the app sleeps when idle. |
| Public GitHub repository | [P] | Met: `https://github.com/leninathikam/necroshield` (public). |
| Root `.kiro` directory committed (not git-ignored) | [P] | Met: `.kiro/steering/`, `.kiro/specs/`, `.kiro/hooks/` are tracked. `.kiro/settings/` and `.kiro/artifacts/` are sandbox-local and untracked. |
| Open-source license | [P] | Met: MIT `LICENSE` at the repository root. |
| Demo video on YouTube, under three minutes, showing the project working | [P] | **Not met yet.** The script is in `docs/demo-script.md` (about 2:45); the participant must record and upload it. |
| Explanation of how Kiro was used | [P] | Draft: `docs/kiro-development.md`. It lists only usage backed by evidence. |
| Original work | [P] | Met, as above. Third-party packages are dependencies under their own licenses. |
| Judge access without credentials | [P] | Met by design: no login; synthetic data only. Paid model execution is not exposed to visitors. |

## Bonus prizes
- **Kiro Crew:** not claimed. No Kiro Crew app was built.
- **Blog post:** not claimed; none written.

## Why it fits Frankenstein
The category asks for technologies that don't normally belong together, stitched into one working application. NecroShield joins five parts that each have their own runtime and trust model:

1. **MCP.** The official MCP SDK server exposes the synthetic tools. A real MCP client session drives the same attack through it.
2. **Deterministic policy enforcement.** A default-deny capability engine sits in front of every tool route: direct runs, MCP, and live model calls. A denied call never reaches tool code.
3. **Model execution.** A live-model loop sends a real model's tool calls through that same gateway. It runs separately from the fixture track and is operator-only.
4. **Counterfactual replay.** Identical intended calls run against a baseline and a protected policy. Single-decision counterfactuals then show which denial changed the outcome.
5. **Independent verification.** A standalone, standard-library verifier with no application imports re-derives outcomes and benchmark arithmetic from the hash-chained evidence.

The stitching is the product. A judge can watch one attack in the web app (Next.js + React Flow, served by FastAPI) go through all five parts:
- it compromises the baseline;
- the policy denies it before dispatch;
- the protected task still completes;
- replaying it over MCP gives the same denial;
- the exported evidence checks out offline.

## Remaining participant actions
1. Re-read the rules page and confirm the table above.
2. Deploy, using `render.yaml` or the Docker image, and run the post-deploy checks in `docs/deployment.md`.
3. Record the YouTube video from `docs/demo-script.md` against the deployed URL.
4. Submit the Devpost form with the repository URL, the app URL, the video, and the Frankenstein category.
