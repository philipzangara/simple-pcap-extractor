# Simple PCAP Extractor- Main entry point
# Accepts a pcap or cap file
# Usage: python simple_pcap_extractor.py file.pcap [--output json]

import argparse 
import json
from pathlib import Path

from display import display
from extractor import extract

def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Type pcap file namee")
    parser.add_argument("log", help="pcap file")
    parser.add_argument("--output", choices=["json"], help="Output format")
    return parser.parse_args(argv)

def main(argv=None) -> None:
    args = parse_args(argv)

    ext = Path(args.log).suffix.lower()
    if ext != ".pcap" and ext != ".cap":
        print("Error: Only .pcap files are supported.")
        raise SystemExit(1)
    
    try:
        ar = extract(args.log)
    except FileNotFoundError:
        print(f"Error: '{args.log}' not found")
        raise SystemExit(1)
    if args.output == "json":
        print(json.dumps(ar.to_dict(), indent=4, default=str))
    else:        
        display(ar)

if __name__ == "__main__":
    main()