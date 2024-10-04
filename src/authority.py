import socketserver
from common import *
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from certificate import *
import pickle

import uuid

ds_dict = {}

class MyUDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        encrypted_data = self.request[0].strip()
        data = SERVER_DECIPHER_RSA.decrypt(encrypted_data)
        socket = self.request[1]
        print("{} wrote:".format(self.client_address[0]))
        print(data)
        
        if b"create_certificate_bob" in data:
            USER_PUBLIC_KEY =  RSA.import_key(data[23:])
            certificate_bob = Certificate("BOB",USER_PUBLIC_KEY.export_key())
            ds = DigitalCertificate(certificate_bob)
            ds_dict["BOB"] = ds
            socket.sendto(b"done", self.client_address)
            
        elif b"create_certificate_alice" in data:
            USER_PUBLIC_KEY =  RSA.import_key(data[25:])
            certificate_alice = Certificate("ALICE",USER_PUBLIC_KEY.export_key())
            ds = DigitalCertificate(certificate_alice)
            ds_dict["ALICE"] = ds
            socket.sendto(b"done", self.client_address)
        elif b"get_certificate_alice" in data:
            socket.sendto(pickle.dumps(ds_dict["ALICE"]),self.client_address)
        elif b"get_certificate_bob" in data:
            socket.sendto(pickle.dumps(ds_dict["BOB"]),self.client_address)
            


if __name__ == "__main__":
    HOST, PORT = "localhost", 9998
    print(f"Certificate Server running on host: {HOST} and port: {PORT} ")
    with socketserver.UDPServer((HOST, PORT), MyUDPHandler) as server:
        server.serve_forever()