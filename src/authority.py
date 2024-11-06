import socketserver
from common import *
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from certificate import *
import pickle

import uuid

ds_dict = {}

PQ_FLAG = True

def send_large_data(data, sock,address, chunk_size=4096):
    # Split data into chunks
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i + chunk_size]
        sock.sendto(chunk, address)
    # Send an empty chunk to indicate the end of the transmission
    sock.sendto(b'', address)

"create_certificate_new <name> <RSA-key> "

class MyUDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        encrypted_data = self.request[0].strip()
        data = SERVER_DECIPHER_RSA.decrypt(encrypted_data)
        socket = self.request[1]
        print("{} wrote:".format(self.client_address[0]))
        print(data)
        
        if b"create_certificate_bob" in data:
            if not PQ_FLAG:
                USER_PUBLIC_KEY =  RSA.import_key(data[23:])
                certificate_bob = Certificate("BOB",USER_PUBLIC_KEY.export_key())
                ds = DigitalCertificate(certificate_bob)
                ds_dict["BOB"] = ds
                socket.sendto(pickle.dumps(ds), self.client_address)
            else:
                USER_PUBLIC_KEY =  RSA.import_key(data[23:])
                certificate_bob = Certificate("BOB",USER_PUBLIC_KEY.export_key())
                ds = PQ_DigitalCertificate(certificate_bob)
                ds_dict["BOB"] = ds
                send_large_data(pickle.dumps(ds), socket,self.client_address)
        elif b"create_certificate_alice" in data:
            if not PQ_FLAG:
                USER_PUBLIC_KEY =  RSA.import_key(data[25:])
                certificate_alice = Certificate("ALICE",USER_PUBLIC_KEY.export_key())
                ds = DigitalCertificate(certificate_alice)
                ds_dict["ALICE"] = ds
                socket.sendto(pickle.dumps(ds), self.client_address)
            else:
                USER_PUBLIC_KEY =  RSA.import_key(data[25:])
                certificate_alice = Certificate("ALICE",USER_PUBLIC_KEY.export_key())
                ds = PQ_DigitalCertificate(certificate_alice)
                ds_dict["ALICE"] = ds
                send_large_data(pickle.dumps(ds), socket, self.client_address)

        elif b"get_certificate_alice" in data:
            socket.sendto(pickle.dumps(ds_dict["ALICE"]),self.client_address)
        elif b"get_certificate_bob" in data:
            socket.sendto(pickle.dumps(ds_dict["BOB"]),self.client_address)

        elif b"create_certificate_user" in data:
            lindex = data.find(b'<')
            rindex = data.find(b'>')
            name = data[lindex+1 : rindex].decode("utf-8")
            USER_PUBLIC_KEY = RSA.import_key(data[rindex + 2:])
            certificate_user = Certificate(name,USER_PUBLIC_KEY.export_key())
            ds = PQ_DigitalCertificate(certificate_user)
            ds_dict[name] = ds

            cert_id = str(certificate_user.serial_no)

            with open("D:\\Netseproject\\netsec-project\src\certificates\CAL_CRL_certs\CAlist.txt", "a") as file:
                file.write(cert_id + "\n")

            socket.sendto(b"Created certificate successfully", self.client_address)

        elif b"revoke_certificate_user" in data:
            lindex = data.find(b'<')
            rindex = data.find(b'>')
            name = data[lindex+1 : rindex].decode("utf-8")
            try:
               ds = ds_dict[name]
            except KeyError:
                print("Certificate doesnt exist in dict")
                send_large_data(pickle.dumps(b"error 102"), socket, self.client_address)
            else:
                cert_id = str(ds.certificate_body.serial_no)

                with open("D:\\Netseproject\\netsec-project\src\certificates\CAL_CRL_certs\CRL.txt", "a") as file:
                    file.write(cert_id + "\n")

                socket.sendto(b"Certificate revoked sucessfully", self.client_address)

        elif b"fetch_certificate_user" in data:
            lindex = data.find(b'<')
            rindex = data.find(b'>')
            name = data[lindex+1 : rindex].decode("utf-8")
            try:
               ds = ds_dict[name]
            except KeyError:
                print("Certificate doesnt exist in dict")
                send_large_data(pickle.dumps(b"error 102"), socket, self.client_address)
            else:    
                cert_id = str(ds.certificate_body.serial_no)

                with open("D:\\Netseproject\\netsec-project\src\certificates\CAL_CRL_certs\CRL.txt", "r") as file:
                    ids = {line.strip() for line in file}

                if cert_id in ids:
                    send_large_data(pickle.dumps(b"error 101"), socket, self.client_address)
                else:
                    with open("D:\\Netseproject\\netsec-project\src\certificates\CAL_CRL_certs\CAlist.txt", "r") as file:
                        cert_ids = {line.strip() for line in file}

                    if cert_id in cert_ids:
                        send_large_data(pickle.dumps(ds_dict[name]), socket, self.client_address)
                    else:
                        send_large_data(pickle.dumps(b"error 102"), socket, self.client_address)
        


if __name__ == "__main__":
    HOST, PORT = "localhost", 9998
    print(f"Certificate Server running on host: {HOST} and port: {PORT} ")
    with socketserver.UDPServer((HOST, PORT), MyUDPHandler) as server:
        server.serve_forever()