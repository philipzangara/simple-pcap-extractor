from analysis_result import AnalysisResult

def display(result: AnalysisResult) -> None:

    print("*** Simple PCAP Extractor v1.0.0 ***")
    print()
    print("*** Protocol Counts ***")
    for protocol, counts in result.protocol_counts.items():
        print(protocol, counts)
    print()
    
    print("*** Top Talkers ***")
    # x[1] is count in (ip, count), sort descending, [:10] first 10 items
    top = sorted(result.top_talkers.items(), key=lambda x: x[1], reverse=True)[:10]
    for ip, count in top:
        print(ip, count)
    print()

    print("*** Connections ***")
    for key, info in result.to_dict()["connections"].items():
        protocol = info.get("protocol", "")
        packets = info.get("packet_count", 0)
        bytes_ = info.get("byte_count", 0)
        duration = info.get("last_seen", 0) - info.get("first_seen", 0)
        print(f"{protocol} {key} packets={packets} bytes={bytes_} duration_sec={duration}")
    print()

    print("*** Top 10 Connections (by bytes) ***")
    top = sorted(
        result.to_dict()["connections"].items(),
        key=lambda kv: int(kv[1].get("byte_count", 0)),
        reverse=True
    )[:10]

    for key, info in top:
        protocol = info.get("protocol", "")
        bytes_ = info.get("byte_count", 0)
        duration = info.get("last_seen", 0) - info.get("first_seen", 0)

        print(f"{protocol} {key} bytes={bytes_} duration_sec={duration}")
    print()

    print(f"*** Files ({len(result.files)}) ***")
    for r in result.files:
        print(f"  File: {r.get('file_name')}")
        print(f"  SHA256: {r.get('sha256')}")
        print(f"  Size: {r.get('byte_count')} bytes")
        print()
