from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from dylithium_py.src.dilithium_py.dilithium import Dilithium5
from certificate import PQ_DigitalCertificate, DigitalCertificate, Certificate
import pickle

# This module converts binary data to hexadecimal
from binascii import hexlify


SERVER_PRIVATE_KEY = RSA.generate(4096*2)
SERVER_PUBLIC_KEY = SERVER_PRIVATE_KEY.publickey()

BOB_PRIVATE_KEY = RSA.generate(1024)
BOB_PUBLIC_KEY = BOB_PRIVATE_KEY.publickey()

ALICE_PRIVATE_KEY = RSA.generate(1024)
ALICE_PUBLIC_KEY = ALICE_PRIVATE_KEY.publickey()

SERVER_DILITHIUM_PUBLIC_KEY, SERVER_DILITHIUM_PRIVATE_KEY = Dilithium5.keygen()

with open("./certificates/server_private_key.pem","wb") as f:
    f.write(SERVER_PRIVATE_KEY.export_key())

with open("./certificates/server_public_key.pem","wb") as f:
    f.write(SERVER_PUBLIC_KEY.export_key())

with open("./certificates/server_dilithium_public_key.crt","wb") as f:
    f.write(SERVER_DILITHIUM_PUBLIC_KEY)

with open("./certificates/server_dilithium_private_key.crt","wb") as f:
    f.write(SERVER_DILITHIUM_PRIVATE_KEY)

with open("./certificates/alice_private_key.pem","wb") as f:
    f.write(ALICE_PRIVATE_KEY.export_key())

with open("./certificates/alice_public_key.pem","wb") as f:
    f.write(ALICE_PUBLIC_KEY.export_key())

with open("./certificates/bob_private_key.pem","wb") as f:
    f.write(BOB_PRIVATE_KEY.export_key())

with open("./certificates/bob_public_key.pem","wb") as f:
    f.write(BOB_PUBLIC_KEY.export_key())


dilithium_private_key_dict = {}
dilithium_public_key_dict = {}

rsa_private_key_dict = {}
rsa_public_key_dict = {}

# Constructing tree hierarchy
ports = [8000, 8001,8002,8003, 8004, 8005, 8006, 8007, 8008]


# generating 9 dilithium public private key pair
for port in ports:
    pk, sk = Dilithium5.keygen()
    
    rsk = RSA.generate(1024)
    rpk = rsk.publickey()
    
    dilithium_private_key_dict[port] = sk
    dilithium_public_key_dict[port] = pk
    
    rsa_private_key_dict[port] = rsk
    rsa_public_key_dict[port] = rpk
    
    with open(f"./certificates/hierarchy/dilithium/public/pq_public_hierarchy_{port}.pem", "wb") as f:
        f.write(pk)
    
    with open(f"./certificates/hierarchy/dilithium/private/pq_private_hierarchy_{port}.pem", "wb") as f:
        f.write(sk)
        
    with open(f"./certificates/hierarchy/rsa/public/public_hierarchy_{port}.pem", "wb") as f:
        f.write(rsk.export_key())
    
    with open(f"./certificates/hierarchy/rsa/private/private_hierarchy_{port}.pem", "wb") as f:
        f.write(rpk.export_key())
            


# pair: {parent_port_number, child_port_number}
# Tree Hierarchy structure
edges = [
    [8000, 8001],
    [8000, 8002],
    [8001, 8003],
    [8001, 8004],
    [8002, 8005],
    [8002, 8006],
    [8003, 8007],
    [8003, 8008]
]

graph = {
    8000:[8001, 8002], 
    8001:[8003, 8004], 
    8002:[8005, 8006], 
    8003:[8007, 8008]
}

parent = {
    8000:8000, 
    8001:8000, 
    8002:8000, 
    8003:8001,
    8004:8001,
    8005:8002,
    8006:8002,
    8007:8003,
    8008:8003,
}


root_node = 8000

def check_valid_certificate(ds: PQ_DigitalCertificate, key) :
    body = ds.certificate_body
    data = pickle.dumps(body)
    val_bytes = bytearray(data)
    temp = ''.join(['%02x' % byte for byte in val_bytes])
    res = Dilithium5.verify(key, str.encode(temp), ds.certificate_signature)
    return res

# Nomenclature for certificates: <type>_<subject>_<issuer>

def _create_forward_certificate(subject_port, issuer_port):
    # print(f"Creating Forward Certificate: issuer {issuer_port}, subject {subject_port}")
    curr_certificate = Certificate(subject_port, rsa_public_key_dict[subject_port].export_key(), issuer_port, subject_port)
    pq_dcert = PQ_DigitalCertificate(curr_certificate, key = dilithium_private_key_dict[issuer_port])
    with open(f"./certificates/hierarchy/dcert/forward_private_hierarchy_{subject_port}_{issuer_port}.pem", "wb+") as f:
        pickle.dump(pq_dcert, f)

def _create_reverse_certificate(subject_port, issuer_port):
    print(f"Creating Reverse Certificate: subject { subject_port}, issuer {issuer_port}")
    curr_certificate = Certificate(subject_port, rsa_public_key_dict[subject_port].export_key(), issuer_port, subject_port)
    pq_dcert = PQ_DigitalCertificate(curr_certificate, key = dilithium_private_key_dict[issuer_port])
    print(check_valid_certificate(pq_dcert,dilithium_public_key_dict[issuer_port] ))
    with open(f"./certificates/hierarchy/dcert/reverse_private_hierarchy_{subject_port}_{issuer_port}.pem", "wb+") as f:
        pickle.dump(pq_dcert, f)

    
    

def _generate_certificates(current_port, parent_port):

    if current_port in graph:
        for child_port in graph[current_port]:
            _create_forward_certificate(child_port, current_port)
            _generate_certificates(child_port, current_port)

    if parent_port != None:
        _create_reverse_certificate(parent_port, current_port)
    else:
        _create_reverse_certificate(current_port, current_port)
        

_generate_certificates(root_node, None) 
