import unittest
from helpers import normalize_connection_key, hash_file, get_file_type

class TestNormalizeConnectionKey(unittest.TestCase):
    def test_connection_key_returns_same(self):
        key1 = normalize_connection_key("192.168.4.5", 13425,
            "204.198.123.143", 80)
        key2 = normalize_connection_key("204.198.123.143", 80, 
                 "192.168.4.5", 13425)
        self.assertEqual(key1, key2)

class TestHashFile(unittest.TestCase):
    def test_hash_file(self):
        file = b"hello"
        file_md5 = "5d41402abc4b2a76b9719d911017c592"
        file_sha256 = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

        self.assertEqual(hash_file(file), (file_md5,
                                            file_sha256)
                                            )

class TestGetFileType(unittest.TestCase):
    def test_get_file_type(self):
        jpeg_file = b"\xff\xd8\xff"
        self.assertEqual(get_file_type(jpeg_file),
                         "image/jpeg")
