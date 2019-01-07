# To be installed:
# Flask==0.12.2: pip install Flask==0.12.2
# Postman HTTP Client: https://www.getpostman.com/
# requests==2.18.4: pip install requests==2.18.4

# Importing the libraries
import ecdsa
import datetime
import hashlib
import json
import base64
from flask import Flask, jsonify, request
import requests
#from uuid import uuid4
from urllib.parse import urlparse

# Defining the Port Values
pkeyport = 5006;

class Blockchain:

    # Init function on blockchain startup
    def __init__(self):
        self.chain = []
        self.iids = set()
        vk = ecdsa.VerifyingKey.from_pem(open("public.pem").read())
        pk = base64.b64encode(vk.to_string()).decode('ascii')
        block = self.create_block(signature = '*', previous_hash = '0', public_key = pk, institution_id = '0', registrant_institution = '0')
        self.add_block(block)
        self.nodes = set()
    
    # Create the block object
    def create_block(self, signature, previous_hash, public_key, institution_id, registrant_institution):
        block = {'index': len(self.chain) + 1,
                 'timestamp': str(datetime.datetime.now()),
                 'signature': signature,
                 'data': {
                         'previous_hash': previous_hash,
                         'public_key': public_key,
                         'institution_id': institution_id,
                         'registrant_institution' : registrant_institution
                         }
        }
        return block
    
    # Append the block to the chain
    def add_block(self, block):
        self.chain.append(block)
        self.iids.add(block['data']['institution_id'])

    # Get the last block of the chain
    def get_previous_block(self):
        return self.chain[-1]
    
    # Verify the block under the Proof of Authority
    def check_block_poa(self, block):
        proof = False;
        previous_block = self.get_previous_block()
        previous_hash = self.hash(previous_block)
        if (previous_hash == block['data']['previous_hash']):
            rid = block['data']['registrant_institution']
            authority_pkey = self.get_registrant_pkey(rid)
            authority_pkey = base64.b64decode(authority_pkey)
            authority_pkey = ecdsa.VerifyingKey.from_string(authority_pkey, curve=ecdsa.NIST256p)
            proof = authority_pkey.verify(base64.b64decode(block['signature']), json.dumps(block['data']).encode())
        if (proof):
            self.add_block(block)
            return True
        else:
            return False
    
    # Hashes the block under the SHA-256 algorithm
    def hash(self, block):
        encoded_block = json.dumps(block, sort_keys = True).encode()
        return hashlib.sha256(encoded_block).hexdigest()
    
    #Check the validity of the chain under the Proof of Authority
    def is_chain_valid(self, chain):
        previous_block = chain[0]
        block_index = 1
        while block_index < len(chain):
            block = chain[block_index]
            if block['previous_hash'] != self.hash(previous_block):
                return False
            rid = block['data']['registrant_institution']
            authority_pkey = self.get_registrant_pkey(rid)
            authority_pkey = base64.b64decode(authority_pkey)
            authority_pkey = ecdsa.VerifyingKey.from_string(authority_pkey, curve=ecdsa.NIST256p)
            proof = authority_pkey.verify(base64.b64decode(block['signature']), json.dumps(block['data']).encode())
            if proof == False:
                return False
            previous_block = block
            block_index += 1
        return True

    
    #Save another node for connection purposes
    def add_node(self, address):
        parsed_url = urlparse(address)
        self.nodes.add(parsed_url.netloc)
    
    #Replace this own chain for the largest one on the network
    def replace_chain(self):
        network = self.nodes
        longest_chain = None
        max_length = len(self.chain)
        for node in network:
            response = requests.get(f'http://{node}/get_chain')
            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']
                if length > max_length and self.is_chain_valid(chain):
                    max_length = length
                    longest_chain = chain
        if longest_chain:
            self.chain = longest_chain
            return True
        return False

    #Get the public keys history
    def get_pkeys_history(self):   
        chain = self.chain
        register = []
        history = []
        for block in chain:
            register.append(block['data']['institution_id'], block['data']['public_key'], block['data']['registrant_institution'])
            list.append(register)
        return history
    
    #Get the Institution public key for requests
    def get_institution_pkey(self, iid):
        chain = self.chain
        for block in reversed(chain):
            if block['data']['institution_id'] == iid:
                return block['data']['public_key']
        return None
    
    #Get the Registrant public key for further local verification
    def get_registrant_pkey(self, registrant_institution):
        chain = self.chain
        for block in reversed(chain):
            if block['data']['institution_id'] == registrant_institution:
                return block['data']['public_key']
        return None


# Creating a Web App
app = Flask(__name__)

# Creating an address for the node on Port 5000
#node_address = str(uuid4()).replace('-', '')

# Creating a Blockchain
blockchain = Blockchain()


@app.route('/get_pkeys', methods = ['GET'])
def get_pkeys():
    keylist = []
    if not keylist:
        return 'Oops error', 400
    return jsonify(keylist), 200


@app.route('/get_institution_pkey', methods = ['POST'])
def get_institution_pkey():
    json = request.get_json()
    iid = json.get('iid')
    if iid is None:
        return "Request is empty", 400
    iidlist = []
    iidlist = blockchain.iids
    if iid not in iidlist:
        return "Requested Id not found into the Blockchain", 400
    pkey = blockchain.get_institution_pkey(iid)
    if pkey is None:
        return "Something is wrong with the Blockchain"
    return jsonify(pkey), 200

# Getting the full Blockchain
@app.route('/get_chain', methods = ['GET'])
def get_chain():
    response = {'chain': blockchain.chain,
                'length': len(blockchain.chain)}
    return jsonify(response), 200

# Checking if the Blockchain is valid
@app.route('/is_valid', methods = ['GET'])
def is_valid():
    is_valid = blockchain.is_chain_valid(blockchain.chain)
    if is_valid:
        response = {'message': 'The Blockchain is valid.'}
    else:
        response = {'message': 'The Blockchain is not valid.'}
    return jsonify(response), 200


@app.route('/submit_pkey', methods = ['POST'])
def submit_pkey():
    json = request.get_json()
    submission_keys = ['data', 'previous_hash', 'public_key', 'institution_id', 'signature', 'registrant_institution']
    for k,v in json.items():
        if k in submission_keys:
            submission_keys.remove(k)
        if isinstance(v,dict):
            for key,value in v.items():
                if key in submission_keys:
                    submission_keys.remove(key)
    if submission_keys:
        return 'Some elements of the transaction are missing', 400
    block = blockchain.create_block(json['signature'], json['data']['previous_hash'], json['data']['public_key'], json['data']['institution_id'], json['data']['registrant_institution'])
    proof = blockchain.check_block_poa(block)
    if proof:
        response = {'message': 'Confirmed Authority! Block added to the chain',
                    'index': block['index'],
                    'timestamp': block['timestamp'],
                    'signature': block['signature'],                   
                    'previous_hash': block['data']['previous_hash'],
                    'identifications': block['data']['public_key'],
                    'institution_id': block['data']['institution_id'],
                    'registrant_institution': block['data']['registrant_institution']
                    }
        code = 200
    else:
        response = {'message': 'Authority not confirmed! Block rejected',
                    'index': block['index'],
                    'timestamp': block['timestamp'],
                    'signature': block['signature'],                   
                    'previous_hash': block['data']['previous_hash'],
                    'identifications': block['data']['public_key'],
                    'institution_id': block['data']['institution_id'],
                    'registrant_institution': block['data']['registrant_institution']
                    }
        code = 400
    return jsonify(response), code

# Connecting new nodes
@app.route('/connect_node', methods = ['POST'])
def connect_node():
    json = request.get_json()
    nodes = json.get('nodes')
    if nodes is None:
        return "No node", 400
    for node in nodes:
        blockchain.add_node(node)
    response = {'message': 'All the nodes are now connected. The PKey Blockchain now contains the following nodes:',
                'total_nodes': list(blockchain.nodes)}
    return jsonify(response), 201

# Replacing the chain by the longest chain if needed
@app.route('/replace_chain', methods = ['GET'])
def replace_chain():
    is_chain_replaced = blockchain.replace_chain()
    if is_chain_replaced:
        response = {'message': 'Chain has been replaced by the longest one.',
                    'new_chain': blockchain.chain}
    else:
        response = {'message': 'Chain is already the largest one.',
                    'actual_chain': blockchain.chain}
    return jsonify(response), 200

# Post an institution ID and Registrant Institution ID to generate a JSON request for testing purposes
@app.route('/create_submission_block', methods = ['POST'])
def create_submission_block():
    json_request = request.get_json()
    institution_id = json_request.get('institution_id')
    registrant_institution = json_request.get('registrant_institution')
    previous_block = blockchain.get_previous_block()
    previous_hash = blockchain.hash(previous_block)
    privkey = ecdsa.SigningKey.generate(curve=ecdsa.NIST256p)
    open("privatePKEYCHAIN.pem","wb").write(privkey.to_pem())
    public_key = privkey.get_verifying_key()
    public_key = base64.b64encode(public_key.to_string()).decode('ascii')
    data = {'previous_hash': previous_hash,
            'public_key': public_key,
            'institution_id': institution_id,
            'registrant_institution': registrant_institution,}
    registrantprivkey = ecdsa.SigningKey.from_pem(open("private.pem").read())
    signature = registrantprivkey.sign(json.dumps(data).encode())
    signature = base64.b64encode(signature).decode('ascii')
    block = {'data': data,
             'signature': signature
            }
    response = str(block)
    response = response.replace("'", '"')
    open("blockPKEYCHAIN.json","w").write(response)
    return 'Pkey Block File Generated', 200

# Running the app
app.run(host = '0.0.0.0', port = pkeyport)
