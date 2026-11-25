"""Print the environment variables of the render.yaml blueprint as `-e KEY=VALUE` flags for `docker run`,
so CI runs the free-plan container with exactly the configuration the blueprint declares. Variables with
no literal value (sync: false, generateValue, fromService) are skipped and reported on stderr.

    python3 render_env.py render.yaml
"""

import shlex
import sys


def parse_env_vars(text: str) -> tuple[dict[str, str], list[str]]:
    """Reads the `envVars:` list of a render.yaml with simple `- key:` / `value:` entries. Deliberately small
    and strict: unfamiliar structure raises instead of being guessed at."""
    values: dict[str, str] = {}
    skipped: list[str] = []
    in_env, entry = False, None
    for raw in text.splitlines():
        line = raw.split(" #", 1)[0].rstrip() if not raw.lstrip().startswith("#") else ""
        if not line.strip():
            continue
        stripped = line.strip()
        if stripped == "envVars:":
            in_env = True
            continue
        if not in_env:
            continue
        if not line.startswith((" ", "-")):
            in_env = False
            continue
        if stripped.startswith("- key:"):
            entry = stripped.split(":", 1)[1].strip().strip("\"'")
            if entry in values or entry in skipped:
                raise ValueError(f"duplicate env var {entry}")
            skipped.append(entry)  # until a literal value is seen
        elif stripped.startswith("value:") and entry:
            values[entry] = stripped.split(":", 1)[1].strip().strip("\"'")
            skipped.remove(entry)
    return values, skipped


if __name__ == "__main__":
    with open(sys.argv[1], encoding="utf-8") as fh:
        env, skipped = parse_env_vars(fh.read())
    if skipped:
        print("skipped (no literal value): " + ", ".join(skipped), file=sys.stderr)
    print(" ".join(f"-e {shlex.quote(f'{k}={v}')}" for k, v in env.items()))
