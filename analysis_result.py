def format_endpoint(ep):
    # Convert (ip, port) tuple to "ip:port" string
    ip, port = ep
    return f"{ip}:{port}"
    
def format_connection_key(connection_key):
    # Unpack normalized bidirectional key into two endpoints and format as "src -> dst"
    (src_ip, src_port), (dst_ip, dst_port) = connection_key
    return f"{format_endpoint((src_ip, src_port))} -> {format_endpoint((dst_ip, dst_port))}"

class AnalysisResult:
    def __init__(self):
        self.connections = {}
        self.protocol_counts = {}
        self.files = []
        self.top_talkers = {}

    def to_dict(self):
        # Convert tuple keys in connections to JSON-serializable strings
        return { "connections": {
            format_connection_key(k): v
                for k, v in self.connections.items()
            },
                "protocol_counts": self.protocol_counts,
                "files": self.files,
                "top_talkers": self.top_talkers
        }
