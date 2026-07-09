import hashlib
import os
import pyclamd

class ScanResult:
    def __init__(self, verdict, engine, detection=None, error=None):
        self.verdict = verdict
        self.engine = engine
        self.detection = detection
        self.error = error

class ScanEngine:
    def scan(self, filepath):
        raise NotImplementedError

class ClamAVEngine(ScanEngine):
    def __init__(self):
        self.cd = pyclamd.ClamdUnixSocket()

    def scan(self, filepath):
        try:
            result = self.cd.scan_file(filepath)
            if result is None:
                return ScanResult('clean', 'ClamAV')
            else:
                detection = list(result.values())[0][1]
                return ScanResult('threat', 'ClamAV', detection=detection)
        except Exception as e:
            return ScanResult('error', 'ClamAV', error=str(e))

def sha256(filepath):
    h = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            h.update(chunk)
    return h.hexdigest()
