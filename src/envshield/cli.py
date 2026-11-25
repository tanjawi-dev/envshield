import argparse
import sys
from pathlib import Path

from envshield import __version__
from envshield.hook import install_pre_commit_hook
from envshield.reporter import Reporter
from envshield.scanner import Scanner


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="envshield",
        description="🛡️ EnvShield: High-speed, zero-dependency secret scanner and pre-commit security tool.",
    )
    parser.add_argument(
        "-v", "--version", action="version", version=f"envshield {__version__}"
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Command: scan
    scan_parser = subparsers.add_parser("scan", help="Scan a directory or file for exposed secrets")
    scan_parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Target directory or file path to scan (defaults to current directory)",
    )
    scan_parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output report format (default: text)",
    )
    scan_parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colors in terminal output",
    )
    scan_parser.add_argument(
        "--ignore-dir",
        action="append",
        default=[],
        help="Directory name to ignore (can be passed multiple times)",
    )
    scan_parser.add_argument(
        "--ignore-pattern",
        action="append",
        default=[],
        help="Glob pattern to ignore (can be passed multiple times)",
    )
    scan_parser.add_argument(
        "--entropy",
        type=float,
        default=4.3,
        help="Shannon entropy threshold for generic secrets (default: 4.3)",
    )
    scan_parser.add_argument(
        "--exit-zero",
        action="store_true",
        help="Exit with code 0 even if secrets or unignored sensitive files are found",
    )

    # Command: install-hook
    hook_parser = subparsers.add_parser(
        "install-hook", help="Install EnvShield as a Git pre-commit hook"
    )
    hook_parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Path to git repository root (defaults to current directory)",
    )

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # Default to scan command if no subcommand provided
    if not args.command or args.command == "scan":
        target_path = getattr(args, "path", ".")
        fmt = getattr(args, "format", "text")
        no_color = getattr(args, "no_color", False)
        ignore_dirs = set(getattr(args, "ignore_dir", []))
        ignore_patterns = getattr(args, "ignore_pattern", [])
        entropy_threshold = getattr(args, "entropy", 4.3)
        exit_zero = getattr(args, "exit_zero", False)

        try:
            scanner = Scanner(
                ignore_dirs=ignore_dirs,
                ignore_patterns=ignore_patterns,
                entropy_threshold=entropy_threshold,
            )
            result = scanner.scan_path(target_path)
            reporter = Reporter(use_colors=not no_color)

            if fmt == "json":
                reporter.print_json_report(result)
            else:
                reporter.print_text_report(result)

            if result.has_violations and not exit_zero:
                return 1
            return 0
        except FileNotFoundError as e:
            sys.stderr.write(f"Error: {e}\n")
            return 2
        except Exception as e:
            sys.stderr.write(f"Unexpected error during scan: {e}\n")
            return 2

    elif args.command == "install-hook":
        target_repo = args.path
        try:
            install_pre_commit_hook(target_repo)
            print(f"✅ Successfully installed EnvShield pre-commit hook at {Path(target_repo).resolve() / '.git/hooks/pre-commit'}")
            return 0
        except Exception as e:
            sys.stderr.write(f"Failed to install git hook: {e}\n")
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
