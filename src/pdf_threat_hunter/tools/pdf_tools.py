from __future__ import annotations
import re
from dataclasses import dataclass
from pathlib import Path

from .safe_shell import SafeShellTool

_pdfid_pattern = re.compile(r"/(\w+)\s+(\d+)")

@dataclass
class PdfIDStats:
    raw: str                         # full stdout
    counts: dict[str, int]           # {"JavaScript": 3, "OpenAction": 1, ...}

    def suspicious_keys(self) -> list[str]:
        return [k for k, v in self.counts.items() if v > 0 and k not in {"Page"}]

def _parse_pdfid_output(stdout: str) -> dict[str, int]:
    return {m.group(1): int(m.group(2)) for m in _pdfid_pattern.finditer(stdout)}

def run_pdfid(pdf_path: str | Path, *, shell: SafeShellTool | None = None) -> PdfIDStats:
    """
    Execute pdfid.py via SafeShell and return structured stats.

    Parameters
    ----------
    pdf_path : str | Path
    shell    : SafeShellTool (optional).  If None, create a temporary one.

    Raises
    ------
    RuntimeError if pdfid execution returns an error.
    """
    shell = shell or SafeShellTool()
    cmd = f'python3 pdfid.py -f "{Path(pdf_path)}"'
    output = shell.invoke(cmd)

    if output.startswith("ERROR"):
        raise RuntimeError(f"pdfid failed: {output}")

    # Keep only STDOUT portion so we don't parse STDERR lines
    stdout = output.split("STDOUT:\n", 1)[-1]
    return PdfIDStats(raw=stdout, counts=_parse_pdfid_output(stdout))