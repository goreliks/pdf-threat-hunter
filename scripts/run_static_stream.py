#!/usr/bin/env python
import sys, json
from textwrap import shorten
from pdf_threat_hunter.agents.static_pdf.runner import stream_analyze

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("Usage: run_static_stream.py <PDF_PATH>")

    pdf = sys.argv[1]
    final_state = None

    for idx, state in enumerate(stream_analyze(pdf, max_iter=20)):
        final_state = state

        iter_no = state.get("current_iteration", "N/A")   # ← safe lookup
        print(f"\n--- Event {idx} | iter={iter_no} ---")

        if cmd := state.get("next_command_to_run"):
            print("Planned command ➜", cmd)

        if state.get("command_history"):
            last_out = state["command_history"][-1]["output"]
            print(shorten(last_out.replace("\n", " "), width=120))

        if state.get("accumulated_findings"):
            print("Findings so far:", state["accumulated_findings"][-1])

    print("\n=== FINAL REPORT ===\n", final_state["final_report"])

    out_file = (
        f"outputs/pdf_analysis_{final_state['pdf_filepath'].split('/')[-1]}.json"
    )
    with open(out_file, "w") as fh:
        json.dump(final_state, fh, indent=2, default=str)
    print("Full state saved to", out_file)