import kerberos
import unittest

class TestKerberosKeyDerivation(unittest.TestCase):
    def test_kerberos(self):
        pid = 100
        password = b"MMQea3n!fsik"
        result = kerberos.derive_kerberos_key(pid, password)
        print("Kerberos key test:", result.hex())
        self.assertEqual(result.hex(), "9ef318f0a170fb46aab595bf9644f9e1")

if __name__ == "__main__":
    unittest.main()