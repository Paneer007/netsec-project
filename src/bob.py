import socket
from common import *
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import hashlib
import pickle
from dylithium_py.src.dilithium_py.dilithium import Dilithium5


HOST, PORT = "localhost", 9998
ALICE_PORT =  9995

BOB_PUBLIC_KEY = None
BOB_PRIVATE_KEY = None

with open("./certificates/bob_private_key.pem","r") as k:
    BOB_PRIVATE_KEY = RSA.importKey(k.read())

with open("./certificates/bob_public_key.pem","r") as k:
    BOB_PUBLIC_KEY = RSA.importKey(k.read())


BOB_DECIPHER_RSA = PKCS1_OAEP.new(BOB_PRIVATE_KEY)

ALICE_PUBLIC_KEY = None
ALICE_CIPHER_RSA = None 

BOB_DIGITAL_CERTIFICATE = None
ALICE_DIGITAL_CERTIFICATE = None

PQ_FLAG = True

def recvall(sock):
    BUFF_SIZE = 4096 # 4 KiB
    data = b''
    while True:
        part = sock.recv(BUFF_SIZE)
        data += part
        if len(part) < BUFF_SIZE:
            break
    return data

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
        hash = hashlib.sha256(data).digest()
        val_bytes = bytearray(hash)
        temp = ''.join(['%02x' % byte for byte in val_bytes])
        res = SERVER_DECIPHER_RSA.decrypt(ds.certificate_signature)
        temp = temp.encode()
        return temp == res

def get_alice_public_key():
    message = b"get_certificate_alice"
    data = SERVER_CIPHER_RSA.encrypt(message)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect((HOST, PORT))
        sock.sendall(data)
        received = recvall(sock)
        ds = pickle.loads(received)
        if not check_valid_certificate(ds):
            print("Invalid Certificate !!!")
            exit(0)
        return RSA.import_key(ds.certificate_body.subject_public_key)

def get_alice_public_key_from_alice(sock):
    data = b"get_certificate_from_alice " + pickle.dumps(BOB_DIGITAL_CERTIFICATE) 
    sock.sendall(data)
    received = recvall(sock)
    ds = pickle.loads(received)
    if not check_valid_certificate(ds):
        print("Invalid Certificate !!!")
        exit(0)
    return RSA.import_key(ds.certificate_body.subject_public_key)


def send_message():
    global ALICE_PUBLIC_KEY
    global ALICE_CIPHER_RSA
    i = 0
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect((HOST, ALICE_PORT))
        ALICE_PUBLIC_KEY = get_alice_public_key_from_alice(s)
        ALICE_CIPHER_RSA = PKCS1_OAEP.new(ALICE_PUBLIC_KEY)
        while i<10:
            usr_data = input("> ")
            data = ALICE_CIPHER_RSA.encrypt(usr_data.encode())
            s.sendall(data)
            data = recvall(s)
            if data == b'':
                data = recvall(s)
                data = BOB_DECIPHER_RSA.decrypt(data)
                continue
            data = BOB_DECIPHER_RSA.decrypt(data)
            i = i+1

def cli_loop():
    while(True):
        print("1- Send Message to Alice")
        print("2- Exit")
        user_input = int(input("Enter Option: "))
        if user_input == 1:
            send_message()
        elif user_input == 2:
            print("Program over")
            exit(0)
        else:
            print("Enter Valid Input")

def create_certificate():
    global BOB_DIGITAL_CERTIFICATE
    message = b"create_certificate_bob " + BOB_PUBLIC_KEY.export_key("OpenSSH")
    data = SERVER_CIPHER_RSA.encrypt(message)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect((HOST, PORT))
        sock.sendall(data)
        received = recvall(sock)
        BOB_DIGITAL_CERTIFICATE = pickle.loads(received)

def cli():
    print("Bob logged in")
    create_certificate()
    cli_loop()

if __name__ == "__main__":
    cli()