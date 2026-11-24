# Kiroween 2026 compliance notes

Checked 2026-11-24.

## Confirmed
- Submission period: October 30 to December 4, 2026. Projects started before October 30 are not eligible ([Devpost](https://kiroween.devpost.com/), via search snippet).
- Frankenstein category: combining seemingly incompatible technologies into one app ([Kiroween 2025 page](https://kiroween-2025.devpost.com/); confirm the 2026 wording).
- Kiro hooks are JSON files at `.kiro/hooks/<id>.json` with `version: "v1"` ([Kiro docs](https://kiro.dev/docs/hooks/)). Steering files use YAML front matter with `inclusion` modes ([Kiro docs](https://kiro.dev/docs/steering/)).

## Not verified
- `https://kiroween.devpost.com/`, `/rules`, and `/details/faqs` returned HTTP 403 to automated fetches from this sandbox. Eligibility details, required submission artifacts, video length limits, and category restrictions still need a manual read by a participant.

## Open items
- The earlier `leninathikam/necroshield` repo is a separate build. This project goes in a new repository so the two histories stay distinct.
