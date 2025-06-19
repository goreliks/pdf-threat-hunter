#!/usr/bin/env python3
import base64, sys, pathlib, argparse, os

ap = argparse.ArgumentParser(description="safe base64 decoder")
ap.add_argument("-d", "--decode", action="store_true", help="decode (like base64 -d)")
ap.add_argument("infile",  nargs="?", default="-")  # - = stdin
ap.add_argument("-o", "--outfile", default="-")      # - = stdout
args = ap.parse_args()

data = sys.stdin.buffer.read() if args.infile == "-" else pathlib.Path(args.infile).read_bytes()
if args.decode:
    data = base64.b64decode(data)
else:
    data = base64.b64encode(data)

if args.outfile == "-":
    sys.stdout.buffer.write(data)
else:
    pathlib.Path(args.outfile).write_bytes(data)
