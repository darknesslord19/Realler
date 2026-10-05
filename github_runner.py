#!/usr/bin/env python3
import argparse
import json
import os
import sys
from pathlib import Path

from server import Analyzer


def main():
    ap = argparse.ArgumentParser(description="V81 GitHub Actions browser analyzer")
    ap.add_argument("url", help="HTTP/HTTPS site URL")
    ap.add_argument("--output", default="v81_output", help="Artifact output directory")
    args = ap.parse_args()

    os.environ.setdefault("V81_GITHUB", "1")
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)

    analyzer = Analyzer()
    try:
        result = analyzer.analyze(args.url)
    except Exception as exc:
        result = {
            "verdict": "ERROR",
            "root": args.url,
            "error": f"{type(exc).__name__}: {exc}",
        }
        import traceback
        (out / "exception.txt").write_text(traceback.format_exc(), encoding="utf-8")
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 1

    (out / "result.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2, default=str), encoding="utf-8"
    )
    (out / "v81_report.json").write_text(
        json.dumps(getattr(analyzer, "v81_report", {}) or {}, ensure_ascii=False, indent=2, default=str),
        encoding="utf-8",
    )
    (out / "logs.txt").write_text("\n".join(str(x) for x in analyzer.logs), encoding="utf-8")
    (out / "browser_network.json").write_text(
        json.dumps(getattr(analyzer, "browser_network", []) or [], ensure_ascii=False, indent=2, default=str),
        encoding="utf-8",
    )
    (out / "browser_requests.json").write_text(
        json.dumps(getattr(analyzer, "browser_requests", []) or [], ensure_ascii=False, indent=2, default=str),
        encoding="utf-8",
    )
    (out / "browser_responses.json").write_text(
        json.dumps(getattr(analyzer, "browser_responses", []) or [], ensure_ascii=False, indent=2, default=str),
        encoding="utf-8",
    )

    print("=" * 70)
    print("V81 GITHUB ANALYSIS")
    print("URL:", args.url)
    print("FINAL:", result.get("final_url") or "NONE")
    print("TYPE:", result.get("final_type") or "NONE")
    print("VERIFIED:", result.get("final_verified"))
    print("DETECT:", result.get("detect"))
    print("BROWSER:", result.get("browser_runtime_used"), result.get("browser_runtime_available"))
    print("OUTPUT:", out.resolve())
    print("=" * 70)
    print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
    return 0 if result.get("final_verified") else 2


if __name__ == "__main__":
    raise SystemExit(main())
