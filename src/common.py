from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import pickle 

SERVER_PRIVATE_KEY = None
SERVER_PUBLIC_KEY = None
SERVER_DILITHIUM_PRIVATE_KEY = None
SERVER_DILITHIUM_PUBLIC_KEY = None

with open("./certificates/server_private_key.pem","r") as k:
    SERVER_PRIVATE_KEY = RSA.importKey(k.read())

with open("./certificates/server_public_key.pem","r") as k:
    SERVER_PUBLIC_KEY = RSA.import_key(k.read())
    
with open("./certificates/server_dilithium_private_key.crt","rb") as k:
    SERVER_DILITHIUM_PRIVATE_KEY = k.read()

with open("./certificates/server_dilithium_public_key.crt","rb") as k:
    SERVER_DILITHIUM_PUBLIC_KEY = k.read()

SERVER_CIPHER_RSA = PKCS1_OAEP.new(SERVER_PUBLIC_KEY)
SERVER_DECIPHER_RSA = PKCS1_OAEP.new(SERVER_PRIVATE_KEY)

data_to_encrypt = b"Hello, this is a message to be encrypted."
encrypted = SERVER_CIPHER_RSA.encrypt(data_to_encrypt)

decrypted = SERVER_DECIPHER_RSA.decrypt(encrypted)

ports = [8000, 8001,8002,8003, 8004, 8005, 8006, 8007, 8008]

DILITHIUM_PUBLIC_KEYS = {}
DILITHIUM_PRIVATE_KEYS = {}

RSA_PUBLIC_KEYS = {}
RSA_PRIVATE_KEYS = {}

FORWARD_CERTIFICATES = {}
REVERSE_CERTIFICATES = {}
OWNED_CERTIFICATE = {}


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

INIT_FLAG = True

if INIT_FLAG:
    # TODO get public keys
    for port in ports:
        with open(f"./certificates/hierarchy/dilithium/public/pq_public_hierarchy_{port}.pem", "rb") as f:
            public_key =  f.read()
            DILITHIUM_PUBLIC_KEYS[port] = public_key
        with open(f"./certificates/hierarchy/rsa/public/public_hierarchy_{port}.pem", "rb") as f:
            public_key = f.read()
            RSA_PUBLIC_KEYS[port] = RSA.import_key(public_key)
    
    
    # TODO get private keys
    for port in ports:
        with open(f"./certificates/hierarchy/dilithium/private/pq_private_hierarchy_{port}.pem", "rb") as f:
            private_key =  f.read()
            DILITHIUM_PRIVATE_KEYS[port] = private_key
        with open(f"./certificates/hierarchy/rsa/private/private_hierarchy_{port}.pem", "rb") as f:
            private_key = f.read()
            RSA_PRIVATE_KEYS[port] = private_key


    # TODO forward certificates
    for port in ports:
        if port not in graph:
            continue
        for child in graph[port]:
            with open(f"./certificates/hierarchy/dcert/forward_private_hierarchy_{child}_{port}.pem", "rb") as f:
                data = pickle.load(f)
                OWNED_CERTIFICATE[child] = data
                if port in FORWARD_CERTIFICATES:
                    FORWARD_CERTIFICATES[port].append(data)
                else:
                    FORWARD_CERTIFICATES[port] = [data]
    
    # TODO reverse certificates
    for port in ports:
        if port not in parent:
            continue
        x = parent[port]
        with open(f"./certificates/hierarchy/dcert/reverse_private_hierarchy_{x}_{port}.pem", "rb") as f:
            data = pickle.load(f)
            REVERSE_CERTIFICATES[port] = data
