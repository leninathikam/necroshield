# Phase 4 evidence — scenarios and command center

Outcome: **passed locally**. The frontend agent executed the final four real
Playwright tests against FastAPI and Next.js on dedicated ports 8017/3017.
The final production Webpack build and TypeScript checks passed. Desktop and
mobile screenshot recaptures also passed after waiting for completed UI state.

```text
python manage.py build
python manage.py e2e
```

The tests create real paired runs, inspect the denied call, download actual
redacted evidence, navigate registry/history, run the backend benchmark, and
exercise keyboard navigation and a 390-pixel mobile viewport without overflow.
They use an isolated local test database, not mocked API responses.

The registry includes document injection, tool-output injection, unauthorized
tool use, local synthetic exfiltration, privilege-boundary violation, memory
poisoning, and a benign invoice control. All six attacks are inert local effects.

Visual inspection checked the graph's baseline/protected lanes, selected denial,
readable decision reasons and redacted arguments, paired task outputs, ordered
timeline, persistent archive, and responsive mobile stacking. Preserved images:

- [Desktop viewport](screenshots/command-center.png)
- [Full desktop page](screenshots/command-center-full.png)
- [Completed mobile run](screenshots/command-center-mobile.png)

The original browser attempt accidentally reused another app on port 3000; it
is not counted as NecroShield acceptance. Dedicated ports resolved that issue
without stopping the other application. Turbopack's CSS subprocess failed on
this Windows/Node environment; supported Next.js Webpack mode passed and is now
the explicit development/build configuration. A typecheck overlapping generated
Next.js files was retried successfully after the build settled.

Accessibility evidence covers keyboard navigation, focus visibility, responsive
containment, semantic controls, and visual review. No comprehensive accessibility
audit or outside user study is claimed.
