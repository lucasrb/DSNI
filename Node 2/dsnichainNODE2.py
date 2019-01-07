# To be installed:
# Flask==0.12.2: pip install Flask==0.12.2
# Postman HTTP Client: https://www.getpostman.com/
# requests==2.18.4: pip install requests==2.18.4

# Importing the libraries
from ecdsa import VerifyingKey, NIST256p, SigningKey
import ast
import datetime
import hashlib
import base64
from hashlib import sha256
import json
from flask import Flask, jsonify, request
import requests
#from uuid import uuid4
from urllib.parse import urlparse

# Defining the Port Values
dsniport = 5001;
pkeyport = 5006;


class Blockchain:

    # Init function on blockchain startup
    def __init__(self):
        self.chain = []
        block = self.create_block(signature = '*', previous_hash = '0', identifications = [], institution_id = '0')
        self.add_block(block)
        self.nodes = set()

    # Create the block object
    def create_block(self, signature, previous_hash, identifications, institution_id):
        block = {'index': len(self.chain) + 1,
                 'timestamp': str(datetime.datetime.now()),
                 'signature': signature,
                 'data': {
                         'previous_hash': previous_hash,
                         'identifications': identifications,
                         'institution_id': institution_id
                         }
        }
        return block
    
    # Append the block to the chain
    def add_block(self, block):
        self.chain.append(block)

    # Get the last block of the chain
    def get_previous_block(self):
        return self.chain[0]

    # Verify the block under the Proof of Authority
    def check_block_poa(self, block):
        proof = False;
        previous_block = self.get_previous_block()
        previous_hash = self.hash(previous_block)
        if (previous_hash == block['data']['previous_hash']):
            iid = block['data']['institution_id']
            authority_pkey = self.get_pkey(iid)
            if authority_pkey == False:
                return False
            authority_pkey = base64.b64decode(authority_pkey)
            authority_pkey = VerifyingKey.from_string(authority_pkey, curve=NIST256p)
            proof = authority_pkey.verify(base64.b64decode(block['signature']), json.dumps(block['data']).encode())
        if (proof):
            blockchain.add_block(block)
            return True
        else:
            return False

    
    def hash(self, block):
        encoded_block = json.dumps(block, sort_keys = True).encode()
        return hashlib.sha256(encoded_block).hexdigest()
    
    
    def is_chain_valid(self, chain):
        previous_block = chain[0]
        block_index = 1
        proof = True;
        while block_index < len(chain):
            block = chain[block_index]
            if block['previous_hash'] != self.hash(previous_block):
                return False
            iid = block['data']['institution_id']
            pkey = self.get_pkey(iid)
            vk = VerifyingKey.from_string(ast.literal_eval(pkey), curve=NIST256p)
            proof = vk.verify(block['signature'], block['data'], hashfunc=sha256)
            if proof == False:
                return False
            previous_block = block
            block_index += 1
        return True
    
    
    def add_node(self, address):
        parsed_url = urlparse(address)
        self.nodes.add(parsed_url.netloc)
    
    
    def replace_chain(self):
        network = self.nodes
        longest_chain = None
        max_length = len(self.chain)
        for node in network:
            response = requests.get('http://127.0.0.1:'+ str(pkeyport) +'/get_pkeys')
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


    def get_pkey(self, institution_id):
        response = requests.post('http://127.0.0.1:'+ str(pkeyport) +'/get_institution_pkey', json={'iid': institution_id})
        if response.status_code == 200:
            return response.content
        else:
            return False
        

# Creating a Web App
app = Flask(__name__)

# Creating an address for the node on defined Port
#node_address = str(uuid4()).replace('-', '')

# Creating a Blockchain
blockchain = Blockchain()

# Adding a new identification block to the Blockchain
@app.route('/submit_block', methods = ['POST'])
def submit_block():
    json_request = request.get_json()
    submission_keys = ['data', 'previous_hash', 'identifications', 'institution_id', 'signature']
    for k,v in json_request.items():
        if k in submission_keys:
            submission_keys.remove(k)
        if isinstance(v,dict):
            for key,value in v.items():
                if key in submission_keys:
                    submission_keys.remove(key)
    if not submission_keys:
        data = json_request['data']
        block = blockchain.create_block(json_request['signature'], data['previous_hash'], data['identifications'], data['institution_id'])
        if blockchain.check_block_poa(block):
            response = {'message': 'Confirmed Authority! Block added to the chain',
                    'index': block['index'],
                    'timestamp': block['timestamp'],
                    'signature': block['signature'],                   
                    'previous_hash': block['data']['previous_hash'],
                    'identifications': block['data']['previous_hash'],
                    'institution_id': block['data']['previous_hash']
                    }
            return jsonify(response), 200
        else:
            return "Block rejected", 400
    else:
        return 'Some elements of the transaction are missing', 400


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


# Connecting new nodes
@app.route('/connect_node', methods = ['POST'])
def connect_node():
    json = request.get_json()
    nodes = json.get('nodes')
    if nodes is None:
        return "No node", 400
    for node in nodes:
        blockchain.add_node(node)
    response = {'message': 'All the nodes are now connected. The DSNI Blockchain now contains the following nodes:',
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

@app.route('/create_submission_block', methods = ['POST'])
def create_submission_block():
    json_request = request.get_json()
    identifications = json_request.get('identifications')
    institution_id = json_request.get('institution_id')
    previous_block = blockchain.get_previous_block()
    previous_hash = blockchain.hash(previous_block)
    data = {"previous_hash": previous_hash,
            'identifications': identifications,
            'institution_id': institution_id}
    sk = SigningKey.from_pem(open("privatePKEYCHAIN.pem").read())
    signature = sk.sign(json.dumps(data).encode())
    signature = base64.b64encode(signature).decode('ascii')
    block = {'data': data,
             'signature': signature
            }
    response = str(block)
    response = response.replace("'", '"')
    open("blockDSNICHAIN.json","w").write(response)
    return 'DSNI Block File Generated', 200

# Running the app
app.run(host = '0.0.0.0', port = dsniport)
