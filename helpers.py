import hashlib
import magic

def normalize_connection_key(src_ip: int, src_port: int,
                             dst_ip: int, dst_port: int) -> tuple:
    
    return tuple(sorted(((src_ip, src_port), (dst_ip, dst_port))))

def hash_file(file: bytes) -> tuple:
    return (hashlib.md5(file).hexdigest(), hashlib.sha256(file).hexdigest())

def get_file_type(file: bytes) -> str:
    return magic.from_buffer(file, mime=True)