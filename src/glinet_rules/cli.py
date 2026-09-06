"""Command line interface.

    python -m glinet_rules build [--output dist] [--previous DIR]
    python -m glinet_rules validate dist/cn-ipv4.txt
    python -m glinet_rules diff dist/ previous/

Every command exits non-zero on failure, so a workflow step that reaches the
publishing stage has, by construction, passed every gate.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import GENERATOR_NAME, __version__
from .config import load_config
from .errors import ConfigError, FetchError, SecurityGateError
from .validate import validate_text_file


def _add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        metavar="DIR",
        help="configuration directory (default: the config/ of the checkout you run from)",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="glinet_rules",
        description="Generate auditable, fail-closed GL.iNet routing rules.",
    )
    parser.add_argument("--version", action="version", version=f"{GENERATOR_NAME} {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    build = sub.add_parser("build", help="fetch upstream data and generate artifacts")
    _add_common(build)
    build.add_argument("--output", type=Path, default=Path("dist"), metavar="DIR")
    build.add_argument(
        "--previous",
        type=Path,
        default=None,
        metavar="DIR",
        help="directory holding the last published artifacts, for diff gates",
    )
    build.add_argument("--audit", type=Path, default=None, metavar="DIR")
    build.add_argument(
        "--no-experimental",
        action="store_true",
        help="skip the experimental IPv6 artifact",
    )
    build.add_argument(
        "--summary",
        type=Path,
        default=None,
        metavar="FILE",
        help="write a markdown build summary (defaults to $GITHUB_STEP_SUMMARY)",
    )

    validate = sub.add_parser("validate", help="check files against the GL.iNet grammar")
    validate.add_argument("paths", nargs="+", type=Path)

    diff = sub.add_parser("diff", help="compare two generated directories")
    diff.add_argument("new_dir", type=Path)
    diff.add_argument("old_dir", type=Path)

    return parser


def _cmd_build(args: argparse.Namespace) -> int:
    from .build import run_build

    config = load_config(args.config)
    result = run_build(
        config,
        output_dir=args.output,
        previous_dir=args.previous,
        audit_dir=args.audit,
        include_experimental=not args.no_experimental,
    )

    print(f"IPv4 networks : {result.ipv4.count:,}")
    print(
        f"IPv4 coverage : {result.ipv4.addresses:,} addresses "
        f"({result.ipv4.percent:.2f}% of IPv4), broadest /{result.ipv4.broadest_prefixlen}"
    )
    print(f"Domains       : {result.domains.count:,}")
    print(f"Combined      : {result.combined_count:,}")
    if result.experimental_ipv6:
        print(f"IPv6 (exp.)   : {result.experimental_ipv6:,}")
    for name, info in result.metadata["files"].items():
        print(f"  {name:16s} {info['lines']:>8,} lines  {info['bytes']:>10,} bytes")
    for warning in result.warnings:
        print(f"WARNING: {warning}", file=sys.stderr)

    summary_path = args.summary or (
        Path(os.environ["GITHUB_STEP_SUMMARY"]) if os.environ.get("GITHUB_STEP_SUMMARY") else None
    )
    if summary_path is not None:
        with summary_path.open("a", encoding="utf-8") as handle:
            handle.write(result.step_summary())
    return 0


def _cmd_validate(args: argparse.Namespace) -> int:
    failures = 0
    for path in args.paths:
        if not path.is_file():
            print(f"{path}: not a file", file=sys.stderr)
            failures += 1
            continue
        result = validate_text_file(path)
        if result.ok:
            summary = ", ".join(f"{k}={v:,}" for k, v in sorted(result.counts.items()) if v)
            print(f"{path}: OK ({result.total:,} rules: {summary})")
            continue
        failures += 1
        print(f"{path}: {len(result.problems)} invalid line(s)", file=sys.stderr)
        for lineno, value, reason in result.problems[:20]:
            print(f"  line {lineno}: {value!r} {reason}", file=sys.stderr)
        if len(result.problems) > 20:
            print(f"  ... and {len(result.problems) - 20} more", file=sys.stderr)
    return 1 if failures else 0


def _cmd_diff(args: argparse.Namespace) -> int:
    from .build import compare_directories

    print(json.dumps(compare_directories(args.new_dir, args.old_dir), indent=2, sort_keys=True))
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handlers = {"build": _cmd_build, "validate": _cmd_validate, "diff": _cmd_diff}
    try:
        return handlers[args.command](args)
    except SecurityGateError as exc:
        print("", file=sys.stderr)
        print("SECURITY GATE FAILED", file=sys.stderr)
        print("", file=sys.stderr)
        print(f"  gate  : {exc.gate}", file=sys.stderr)
        print(f"  reason: {exc.detail}", file=sys.stderr)
        print("", file=sys.stderr)
        print("Publication blocked. The previous release remains active.", file=sys.stderr)
        return 2
    except (ConfigError, FetchError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
