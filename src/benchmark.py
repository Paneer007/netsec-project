from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from certificate import *
import time



SERVER_PRIVATE_KEY = None
SERVER_PUBLIC_KEY = None
SERVER_DILITHIUM_PRIVATE_KEY = None
SERVER_DILITHIUM_PUBLIC_KEY = None

USER_PUBLIC_KEY = None
USER_PRIVATE_KEY = None

with open("./certificates/bob_private_key.pem","r") as k:
    USER_PRIVATE_KEY = RSA.importKey(k.read())

with open("./certificates/bob_public_key.pem","r") as k:
    USER_PUBLIC_KEY = RSA.importKey(k.read())

with open("./certificates/alice_private_key.pem","r") as k:
    SERVER_PRIVATE_KEY = RSA.importKey(k.read())

with open("./certificates/alice_public_key.pem","r") as k:
    SERVER_PUBLIC_KEY = RSA.importKey(k.read())

with open("./certificates/server_dilithium_private_key.crt","rb") as k:
    SERVER_DILITHIUM_PRIVATE_KEY = k.read()

with open("./certificates/server_dilithium_public_key.crt","rb") as k:
    SERVER_DILITHIUM_PUBLIC_KEY = k.read()
    
SERVER_CIPHER_RSA = PKCS1_OAEP.new(SERVER_PUBLIC_KEY)
SERVER_DECIPHER_RSA = PKCS1_OAEP.new(SERVER_PRIVATE_KEY)

name = "Sanjai"

PQ_FLAG = True

def check_valid_certificate(ds):
    if PQ_FLAG: 
        body = ds.certificate_body
        data = pickle.dumps(body)
        val_bytes = bytearray(data)
        temp = ''.join(['%02x' % byte for byte in val_bytes])
        res = Dilithium5.verify(SERVER_DILITHIUM_PUBLIC_KEY,str.encode(temp), ds.certificate_signature)
        return res
    else:
        body = ds.certificate_body
        data = pickle.dumps(body)
        hash = SHA256.new(data)
        try:
            SERVER_SIG_VERIFIER.verify(hash,ds.certificate_signature)
        except Exception as err:
            print(err)
            return False
        return True


def test_pq():
    if not PQ_FLAG:
        certificate_user = Certificate(name,USER_PUBLIC_KEY.export_key())
        ds = DigitalCertificate(certificate_user)
        check_valid_certificate(ds)
    else:
        certificate_user = Certificate(name,USER_PUBLIC_KEY.export_key())
        ds = PQ_DigitalCertificate(certificate_user)
        check_valid_certificate(ds)
    pass 

if __name__ == "__main__":
    start_time = time.time()
    for i in range(0,100):
        test_pq()
    print("--- %s seconds ---" % (time.time() - start_time))
