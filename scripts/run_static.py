#!/usr/bin/env python3

import sys, json
from pdf_threat_hunter.agents.static_pdf.runner import analyze

if __name__ == "__main__":
    pdf = sys.argv[1]
    result = analyze(pdf)
    print(json.dumps(result["final_report"], indent=2))
    # or pretty-print json.dumps(state["final_report"], indent=2)