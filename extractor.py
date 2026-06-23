from scapy.all import PcapReader, IP, TCP, UDP, Raw #type: ignore
from scapy.layers.http import HTTP, HTTPResponse
import re

from analysis_result import AnalysisResult
from helpers import normalize_connection_key, get_file_type, hash_file

def extract_http_files(packet, result: AnalysisResult) -> None:
    # Extracts file metadata from HTTP responses. Appends to result.files in place.

    if not packet.haslayer(Raw) or not hasattr(packet[Raw], "load"):
        return

    response = packet[HTTPResponse] 

    body = bytes(packet[Raw].load)

    if not body:
        return
    
    content_type = getattr(response, "Content_Type", None) or getattr(response, "Content-Type", None)
    content_type = content_type.decode() if isinstance(content_type, bytes) else content_type
    
    file_hash = hash_file(body)
    file_type = get_file_type(body)

    cd = getattr(response, "Content_Disposition", None) or getattr(response, "Content-Disposition", None)

    if not cd:
        file_name = "extracted_file"
    else:
        m = re.search(r'filename\*?=(?:\"?)([^\";]+)', cd, flags=re.IGNORECASE)
        file_name = m.group(1).strip() if m else "extracted_file"

    md5, sha256 = file_hash
    

    result.files.append({
        "content_type": content_type,
        "file_type": file_type,
        "file_name": file_name,
        "md5": md5,
        "sha256": sha256,
        "byte_count": len(body),
        "first_seen": getattr(packet, "time", None),
        })

def extract(pcap_path: str) -> AnalysisResult:
    result = AnalysisResult()

    with PcapReader(pcap_path) as reader:

        for packet in reader:
            # Skip non-IP traffic 
            if not packet.haslayer(IP):
                continue
            
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # Extract ports if TCP/UDP, otherwise None
            src_port = packet[TCP].sport if packet.haslayer(TCP) else \
                       packet[UDP].sport if packet.haslayer(UDP) else None
            dst_port = packet[TCP].dport if packet.haslayer(TCP) else \
                       packet[UDP].dport if packet.haslayer(UDP) else None
            
            # Normalize to bidirectional key so A->B and B->A map to the same connection
            key = normalize_connection_key(src_ip, src_port, dst_ip, dst_port)

            if packet.haslayer(TCP):
                protocol = "TCP"
            elif packet.haslayer(UDP):
                protocol = "UDP"
            else:
                protocol = "Other"
            
            # Initialize connection entry on first sight, no-op on subsequent packets
            result.connections.setdefault(key, {
                "protocol": protocol,
                "packet_count": 0,
                "first_seen": packet.time,
                "last_seen": packet.time,
                "byte_count": 0
            })

            result.connections[key]["packet_count"] += 1
            result.connections[key]["last_seen"] = packet.time
            result.connections[key]["byte_count"] += len(packet)

            # Count packets per protocol
            result.protocol_counts.setdefault(protocol, 0)
            result.protocol_counts[protocol] += 1

            # Count packets per source ip
            result.top_talkers.setdefault(src_ip, 0)
            result.top_talkers[src_ip] += 1

            if packet.haslayer(HTTPResponse):
                extract_http_files(packet, result)
    
    return result

