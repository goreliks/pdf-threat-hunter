from __future__ import annotations
import uuid
from collections import ChainMap
from typing import Iterator

from .graph import app


# ---------------------------------------------------------------------
def _initial_input(pdf_path: str, *, max_iter: int) -> dict:
    return {
        "pdf_filepath": pdf_path,
        "original_user_request": f"Analyze the PDF file at {pdf_path}",
        "max_iterations": max_iter,
        "messages": [],
    }


# ---------------------------------------------------------------------
def analyze(pdf_path: str, *, max_iter: int = 10) -> dict:
    """Blocking helper – returns the final state."""
    return app.invoke(
        _initial_input(pdf_path, max_iter=max_iter),
        config={"configurable": {"thread_id": str(uuid.uuid4())}},
    )


# ---------------------------------------------------------------------
def stream_analyze(pdf_path: str, *, max_iter: int = 10) -> Iterator[dict]:
    """
    Yield the **cumulative state** after each node, so every yield contains
    current_iteration, command_history, accumulated_findings, etc.
    """
    cumulative: dict = {}
    for patch in app.stream(
        _initial_input(pdf_path, max_iter=max_iter),
        config={"configurable": {"thread_id": str(uuid.uuid4())}},
        stream_mode="values",
    ):
        cumulative = dict(ChainMap(patch, cumulative))
        yield cumulative