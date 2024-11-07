from common import *
from certificate import *
from dylithium_py.src.dilithium_py.dilithium import Dilithium5
import networkx as nx 
import matplotlib.pyplot as plt 

ALICE_PORT = 8008
BOB_PORT = 8004

ALICE_CERTIFICATE = OWNED_CERTIFICATE[ALICE_PORT]
BOB_CERTIFICATE = OWNED_CERTIFICATE[BOB_PORT]


alice_parent_certificates = [ALICE_CERTIFICATE]
bob_parent_certificates = [BOB_CERTIFICATE]


alice_parent = [ALICE_PORT]
bob_parent = [BOB_PORT]

lca_parent = None
lca_cert = None


final_edges = []

IS_ALICE = False

def check_valid_certificate(ds: PQ_DigitalCertificate, key) :
    body = ds.certificate_body
    data = pickle.dumps(body)
    val_bytes = bytearray(data)
    temp = ''.join(['%02x' % byte for byte in val_bytes])
    res = Dilithium5.verify(key, str.encode(temp), ds.certificate_signature)
    return res

def _get_reverse_certificate(port) -> PQ_DigitalCertificate:
    return REVERSE_CERTIFICATES[port]

def _get_forward_certificate(issuer_port, subject_port):
    certs = FORWARD_CERTIFICATES[issuer_port]
    for cert in certs:
        if cert.certificate_body.subject_unique_identifier == subject_port:
            return cert
    
    raise Exception("Forward certificate does not exist")

def _get_verify_reverse_root_certificate(certificate: PQ_DigitalCertificate):
    # Loop
    while (True):
        # port number
        port = certificate.certificate_body.subject_unique_identifier
        # get public key of signer
        # public_key = certificate.certificate_body.subject_public_key
        public_key = DILITHIUM_PUBLIC_KEYS[certificate.certificate_body.subject_unique_identifier]
        
        # Get reverse certificate
        rev_cert = _get_reverse_certificate(certificate.certificate_body.subject_unique_identifier)
        # Check if reverse certificate is by node itself
        if rev_cert.certificate_body.issuer_unique_identifier == rev_cert.certificate_body.subject_unique_identifier:
            return rev_cert
        # Validate Reverse Certificate
        
        if not check_valid_certificate(rev_cert, public_key):
            raise Exception("Invalid certificate")
        if IS_ALICE:
            # Push reverse Certificate to parent list
            alice_parent_certificates.append(rev_cert)
            # Push to port number to parent list 
            alice_parent.append(rev_cert.certificate_body.subject_unique_identifier)
        else:
            bob_parent_certificates.append(rev_cert)
            bob_parent.append(rev_cert.certificate_body.subject_unique_identifier)
        # Update certificate
        certificate = rev_cert

def _get_lca_from_certificate(root_certificate):
    global lca_parent
    global lca_cert
    global final_edges
    
    # Loop 
    while (True):
        # Pop off alice top node
        alice_top = alice_parent.pop()
        alice_prev_cert = alice_parent_certificates.pop()
        
        # Pop off bob top node
        bob_top = bob_parent.pop()
        bob_prev_cert = bob_parent_certificates.pop()

        # If nodes equal, store last node and continue
        if alice_top == bob_top:
            lca_parent = bob_top
            lca_cert = bob_prev_cert
        else:
        # If nodes are not equal, push back to list and return last node
            alice_parent.append(alice_top)
            bob_parent.append(bob_top)
            alice_parent_certificates.append(alice_prev_cert)
            bob_parent_certificates.append(bob_prev_cert)
            
            final_edges = bob_parent
            final_edges.append(lca_parent)
            return [lca_parent, lca_cert]

        # repeat 
        pass

def _get_verify_leaf_node_forward_certificate(LCA_CERTIFICATE:PQ_DigitalCertificate):
    global final_edges
    
    # Loop
    while(True):
        # Pop off alice top node,
        alice_top =  alice_parent.pop()
        alice_prev_cert =  alice_parent_certificates.pop()

        # get public key
        # public_key = LCA_CERTIFICATE.certificate_body.subject_public_key
        public_key  = DILITHIUM_PUBLIC_KEYS[LCA_CERTIFICATE.certificate_body.subject_unique_identifier]

        # Get forward node corresponding to that node (i.e certificate)
        forward_cert = _get_forward_certificate(LCA_CERTIFICATE.certificate_body.subject_unique_identifier, alice_prev_cert.certificate_body.subject_unique_identifier)
        
        # Verify if valid certificate
        if not check_valid_certificate(forward_cert, public_key):
            raise Exception("Invalid certificate")        
        
        LCA_CERTIFICATE = alice_prev_cert
        final_edges.append(alice_top)
        # Repeat till all nodes in reverse root are validated 
        if(len(alice_parent) == 0):
            return True


def _print_path():
    global final_edges
    G = nx.Graph() 
    # Generate tree
    for edge in edges:
        G.add_edge(edge[0], edge[1],color='r', weight=2)
    
    for i in range(0, len(final_edges) -1):
        G.add_edge(final_edges[i], final_edges[i+1], color='b', weight=6)
        
    pos = nx.circular_layout(G)
    tedge = G.edges()
    colors = [G[u][v]['color'] for u,v in tedge]
    weights = [G[u][v]['weight'] for u,v in tedge]
    nx.draw(G, pos,  edge_color=colors, width=weights, with_labels=True)
    plt.show() 
    
    

def verify_chain_of_certificate(ALICE_CERTIFICATE, BOB_CERTIFICATE):
    global IS_ALICE

    bob_root_certificate = _get_verify_reverse_root_certificate(BOB_CERTIFICATE)
    IS_ALICE = True
    alice_root_certificate = _get_verify_reverse_root_certificate(ALICE_CERTIFICATE)


    if alice_root_certificate != bob_root_certificate:
        print("There does not exist a chain of trust b/w Alice and Bob")
        exit(0)
    output = _get_lca_from_certificate(alice_root_certificate)
    
    LCA_CERTIFICATE = output[1]
    path_exist = _get_verify_leaf_node_forward_certificate(LCA_CERTIFICATE)
    
    if path_exist:
        print("The certificates generate by alice and bob are both valid and there exist a chain of trust b/w alice and bob")
        _print_path()
    else:
        print("Skill issue")
    

if __name__ == "__main__":
    print("Bob wants to verify the hierarchy")
    verify_chain_of_certificate(ALICE_CERTIFICATE, BOB_CERTIFICATE)

        
    