import argparse
import sys
from pathlib import Path

from envshield import __version__
from envshield.hook import install_pre_commit_hook, uninstall_pre_commit_hook
from envshield.reporter import Reporter
from envshield.scanner import Scanner
from envshield.staged import StagedScanner


def add_common_scan_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Target directory or file path to scan (default: current directory)",
    )
    parser.add_argument(
        "--staged",
        action="store_true",
        help="Scan only files staged in the Git index (ideal for pre-commit hooks)",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output report format (default: text)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colors in terminal output",
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Quiet mode: suppress non-essential output, only report errors or exit code",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose mode: show skipped files and extra scanning diagnostics without revealing secrets",
    )
    parser.add_argument(
        "--ignore-dir",
        action="append",
        default=[],
        help="Directory name to ignore (can be passed multiple times)",
    )
    parser.add_argument(
        "--ignore-pattern",
        action="append",
        default=[],
        help="Glob pattern to ignore (can be passed multiple times)",
    )
    parser.add_argument(
        "--entropy",
        type=float,
        default=4.3,
        help="Shannon entropy threshold for generic secrets (default: 4.3)",
    )
    parser.add_argument(
        "--max-size",
        type=int,
        default=10,
        help="Maximum file size to scan in megabytes (default: 10 MB)",
    )
    parser.add_argument(
        "--exit-zero",
        action="store_true",
        help="Exit with code 0 even if secrets or unignored sensitive files are found",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="envshield",
        description="🛡️ EnvShield: High-speed, zero-dependency secret scanner and pre-commit security tool.",
    )
    parser.add_argument(
        "--version", action="version", version=f"envshield {__version__}"
    )

    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Command: scan
    scan_parser = subparsers.add_parser("scan", help="Scan a directory, file, or staged Git index for exposed secrets")
    add_common_scan_args(scan_parser)

    # Command: check (convenient alias for scan)
    check_parser = subparsers.add_parser("check", help="Alias for 'scan'")
    add_common_scan_args(check_parser)

    # Command: install-hook
    hook_parser = subparsers.add_parser(
        "install-hook", help="Install EnvShield as a safe Git pre-commit hook"
    )
    hook_parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Path to git repository root (default: current directory)",
    )
    hook_parser.add_argument(
        "--force",
        action="store_true",
        help="Force installation and backup existing foreign pre-commit hook",
    )

    # Command: uninstall-hook
    unhook_parser = subparsers.add_parser(
        "uninstall-hook", help="Uninstall EnvShield pre-commit hook and restore any previous backup"
    )
    unhook_parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Path to git repository root (default: current directory)",
    )

    # Command: version
    subparsers.add_parser("version", help="Print envshield version")

    return parser


def run_scan(args: argparse.Namespace) -> int:
    target_path = getattr(args, "path", ".")
    is_staged = getattr(args, "staged", False)
    fmt = getattr(args, "format", "text")
    no_color = getattr(args, "no_color", False)
    quiet = getattr(args, "quiet", False)
    verbose = getattr(args, "verbose", False)
    ignore_dirs = set(getattr(args, "ignore_dir", []))
    ignore_patterns = getattr(args, "ignore_pattern", [])
    entropy_threshold = getattr(args, "entropy", 4.3)
    max_size_mb = getattr(args, "max_size", 10)
    exit_zero = getattr(args, "exit_zero", False)

    try:
        if is_staged:
            scanner = StagedScanner(
                entropy_threshold=entropy_threshold,
                max_file_size_bytes=max_size_mb * 1024 * 1024,
            )
            result = scanner.scan_staged(target_path)
        else:
            scanner = Scanner(
                ignore_dirs=ignore_dirs,
                ignore_patterns=ignore_patterns,
                entropy_threshold=entropy_threshold,
                max_file_size_bytes=max_size_mb * 1024 * 1024,
            )
            result = scanner.scan_path(target_path)

        reporter = Reporter(use_colors=not no_color, quiet=quiet, verbose=verbose)

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
        sys.stderr.write(f"Unexpected error during scan: {type(e).__name__}\n")
        return 2


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command or args.command in ("scan", "check"):
        return run_scan(args)

    elif args.command == "version":
        print(f"envshield {__version__}")
        return 0

    elif args.command == "install-hook":
        target_repo = args.path
        force = getattr(args, "force", False)
        try:
            success, message = install_pre_commit_hook(target_repo, force=force)
            if success:
                print(f"✅ {message}")
                return 0
            else:
                sys.stderr.write(f"❌ {message}\n")
                return 1
        except Exception as e:
            sys.stderr.write(f"Failed to install git hook: {e}\n")
            return 2

    elif args.command == "uninstall-hook":
        target_repo = args.path
        try:
            success, message = uninstall_pre_commit_hook(target_repo)
            if success:
                print(f"✅ {message}")
                return 0
            else:
                sys.stderr.write(f"❌ {message}\n")
                return 1
        except Exception as e:
            sys.stderr.write(f"Failed to uninstall git hook: {e}\n")
            return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
