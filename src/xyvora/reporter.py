"""Report generation: creates report.md summarizing all module results."""

import os
from datetime import datetime

from .utils import Result


def generate(target: str, out_dir: str, services: dict[int, dict], module_results: dict[str, list[Result]], elapsed: float) -> str:
    """Generate report.md and return its path."""
    path = os.path.join(out_dir, "report.md")
    lines = []

    lines.append(f"# xyvora Report — {target}")
    lines.append("")
    lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"**Total time:** {elapsed:.0f}s")
    lines.append("")

    # Service summary
    if services:
        lines.append("## Open Ports / Services")
        lines.append("")
        lines.append("| Port | Service | Product | Version |")
        lines.append("|------|---------|---------|---------|")
        for port, info in sorted(services.items()):
            lines.append(f"| {port} | {info.get('name', '?')} | {info.get('product', '-')} | {info.get('version', '-')} |")
        lines.append("")

    # Module results
    for category, results in sorted(module_results.items()):
        non_empty = [r for r in results if r.has_output]
        if not non_empty:
            continue
        lines.append(f"## {category.upper()}")
        lines.append("")
        for r in non_empty:
            lines.append(f"### {r.label}")
            lines.append(f"**Status:** {'success' if r.success else 'failed'} | **Time:** {r.elapsed:.1f}s")
            lines.append("")
            lines.append("```")
            # Truncate very long outputs
            output = r.stdout[:5000] if len(r.stdout) > 5000 else r.stdout
            if len(r.stdout) > 5000:
                output += "\n... (truncated)"
            lines.append(output.strip())
            lines.append("```")
            lines.append("")

    # Empty report warning
    if all(not r.has_output for results in module_results.values() for r in results):
        lines.append("## No results")
        lines.append("")
        lines.append("All modules returned empty output. The target may be unreachable or no services were detected.")
        lines.append("")

    with open(path, "w", encoding="utf-8", errors="replace") as f:
        f.write("\n".join(lines))

    return path
