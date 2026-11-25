import json
import sys
from typing import Optional, TextIO

from envshield.scanner import ScanResult


class TerminalColors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GRAY = "\033[90m"


def colorize(text: str, color: str, enabled: bool = True) -> str:
    if not enabled or not sys.stdout.isatty():
        return text
    return f"{color}{text}{TerminalColors.RESET}"


class Reporter:
    def __init__(self, use_colors: bool = True, quiet: bool = False, verbose: bool = False):
        self.use_colors = use_colors
        self.quiet = quiet
        self.verbose = verbose

    def print_text_report(self, result: ScanResult, out: Optional[TextIO] = None) -> None:
        if out is None:
            out = sys.stdout
        c = self.use_colors

        if self.quiet:
            if result.has_violations:
                out.write(colorize("❌ Security violations detected by EnvShield.\n", TerminalColors.BOLD + TerminalColors.RED, c))
            return

        out.write("\n" + colorize("🛡️  EnvShield Security Scanner", TerminalColors.BOLD + TerminalColors.CYAN, c) + "\n")
        out.write(colorize("=" * 60, TerminalColors.GRAY, c) + "\n\n")

        # 1. Print sensitive files warnings
        unignored_files = [f for f in result.sensitive_files if not f.is_git_ignored]
        if unignored_files:
            out.write(colorize("⚠️  CRITICAL: Unprotected Sensitive Files Detected", TerminalColors.BOLD + TerminalColors.YELLOW, c) + "\n")
            out.write(colorize("These files are sensitive and NOT properly ignored:\n", TerminalColors.GRAY, c))
            for alert in unignored_files:
                out.write(f"  • {colorize(alert.file_path, TerminalColors.RED, c)} ({alert.reason})\n")
            out.write("\n")

        # 2. Print found secrets
        if result.findings:
            out.write(colorize("🚨 SECRETS DETECTED", TerminalColors.BOLD + TerminalColors.RED, c) + "\n")
            for finding in result.findings:
                sev_color = TerminalColors.RED if finding.severity == "CRITICAL" else TerminalColors.YELLOW
                sev_badge = colorize(f"[{finding.severity}]", TerminalColors.BOLD + sev_color, c)
                loc = colorize(f"{finding.file_path}:{finding.line_number}", TerminalColors.CYAN, c)

                out.write(f"\n  {sev_badge} {colorize(finding.rule_name, TerminalColors.BOLD, c)}\n")
                out.write(f"    Location: {loc}\n")
                out.write(f"    Pattern:  {finding.masked_value}\n")
                out.write(f"    Snippet:  {colorize(finding.snippet, TerminalColors.GRAY, c)}\n")
            out.write("\n")

        # Verbose notices (skipped files)
        if self.verbose:
            if result.skipped_large_files:
                out.write(colorize("ℹ️  Skipped Large Files (> size limit):\n", TerminalColors.BLUE, c))
                for f_path in result.skipped_large_files:
                    out.write(f"    - {f_path}\n")
            if result.skipped_unreadable_files:
                out.write(colorize("ℹ️  Skipped Unreadable Files:\n", TerminalColors.BLUE, c))
                for f_path in result.skipped_unreadable_files:
                    out.write(f"    - {f_path}\n")
            if result.skipped_large_files or result.skipped_unreadable_files:
                out.write("\n")

        # 3. Summary section
        out.write(colorize("-" * 60, TerminalColors.GRAY, c) + "\n")
        files_label = f"Files Scanned: {result.scanned_files_count}"
        lines_label = f"Lines Scanned: {result.scanned_lines_count}"
        duration_label = f"Time: {result.duration_seconds}s"
        out.write(f"{files_label} | {lines_label} | {duration_label}\n")

        if result.has_violations:
            total_violations = len(result.findings) + len(unignored_files)
            summary_msg = f"❌ Scan Failed: {total_violations} security violation(s) identified!"
            out.write(colorize(summary_msg, TerminalColors.BOLD + TerminalColors.RED, c) + "\n\n")
        else:
            summary_msg = "✅ Scan Clean: No exposed credentials or secrets detected."
            out.write(colorize(summary_msg, TerminalColors.BOLD + TerminalColors.GREEN, c) + "\n\n")

    def print_json_report(self, result: ScanResult, out: Optional[TextIO] = None) -> None:
        if out is None:
            out = sys.stdout
        data = {
            "summary": {
                "scanned_files": result.scanned_files_count,
                "scanned_lines": result.scanned_lines_count,
                "duration_seconds": result.duration_seconds,
                "clean": not result.has_violations,
                "findings_count": len(result.findings),
                "unignored_sensitive_files_count": len([f for f in result.sensitive_files if not f.is_git_ignored]),
                "skipped_large_files_count": len(result.skipped_large_files),
                "skipped_unreadable_files_count": len(result.skipped_unreadable_files),
            },
            "findings": [
                {
                    "file": f.file_path,
                    "line": f.line_number,
                    "rule": f.rule_name,
                    "severity": f.severity,
                    "masked_secret": f.masked_value,
                    "snippet": f.snippet,
                }
                for f in result.findings
            ],
            "sensitive_files": [
                {
                    "file": f.file_path,
                    "reason": f.reason,
                    "is_git_ignored": f.is_git_ignored,
                }
                for f in result.sensitive_files
            ],
        }
        json.dump(data, out, indent=2)
        out.write("\n")
