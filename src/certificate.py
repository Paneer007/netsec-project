import hashlib
import pickle
from common import * 
import uuid
from datetime import datetime, timedelta
from dylithium_py.src.dilithium_py.dilithium import Dilithium5

class Certificate:
    version_no = None
    serial_no = None
    signature_algo_id = None
    issuer_name = None
    validity_not_before = None
    validity_not_after = None
    subject_name = None
    subject_public_key = None
    subject_public_key_algorithm = None

    issuer_unique_identifier = None
    subject_unique_identifier = None
    
    def __init__(self, subject_name, subject_public_key, iui = None, sui = None):
        self.version_no = 1
        self.serial_no = uuid.uuid4()
        self.signature_algo_id = 1
        self.issuer_name = "CA"
        self.validity_not_before = datetime.now()
        self.validity_not_after = datetime.now() + timedelta(days=2)
        self.subject_name = subject_name
        self.subject_public_key = subject_public_key
        self.subject_public_key_algorithm = "RSA"
        self.issuer_unique_identifier = iui
        self.subject_unique_identifier = sui
    
    
    
class DigitalCertificate:
    certificate_body = None
    certificate_signature = None
    certificate_algorithm = None
    
    def __init__(self,body) -> None:
        self.certificate_body=body
        data = pickle.dumps(body)
        hash = hashlib.sha256(data).digest()
        val_bytes = bytearray(hash)
        temp = ''.join(['%02x' % byte for byte in val_bytes])
        self.certificate_signature = SERVER_CIPHER_RSA.encrypt(str.encode(temp))
        self.certificate_algorithm = "SHA+RSA"

    
class PQ_DigitalCertificate:
    certificate_body: Certificate = None
    certificate_signature = None
    certificate_algorithm = None
    
    def __init__(self,body, key = None) -> None:
        if key == None:
            key = SERVER_DILITHIUM_PRIVATE_KEY
        self.certificate_body=body
        data = pickle.dumps(body)
        # hash = hashlib.sha256(data).digest()
        val_bytes = bytearray(data)
        temp = ''.join(['%02x' % byte for byte in val_bytes])
        self.certificate_signature= Dilithium5.sign(key, str.encode(temp))
        self.certificate_algorithm = "DILITHIUM"
 