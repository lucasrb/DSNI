# Module 2 - Create a Cryptocurrency

# To be installed:
# Flask==0.12.2: pip install Flask==0.12.2
# Postman HTTP Client: https://www.getpostman.com/
# requests==2.18.4: pip install requests==2.18.4

# Importing the libraries
from ecdsa import VerifyingKey, NIST256p, SigningKey
import ast
import datetime
import hashlib
from hashlib import sha256
import json
from flask import Flask, jsonify, request
import requests
from uuid import uuid4
from urllib.parse import urlparse

# Part 1 - Building a Blockchain

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
            # necessário pegar a verifying key do bloco, provável que através de outra blockchain
            pkey = self.get_pkey(block['data']['institution_id'])
            vk = VerifyingKey.from_string(ast.literal_eval(pkey), curve=NIST256p)
            proof = vk.verify(block['signature'], block['data'], hashfunc=sha256)
        print('running check poa')
        if (proof):
            print('proof check poa')
            blockchain.add_block(block)
            return True
        else:
            print('else check poa')
            return False

    
    def hash(self, block):
        encoded_block = json.dumps(block, sort_keys = True).encode()
        return hashlib.sha256(encoded_block).hexdigest()
    
    
    def is_chain_valid(self, chain):
        previous_block = chain[0]
        block_index = 1
        while block_index < len(chain):
            block = chain[block_index]
            if block['previous_hash'] != self.hash(previous_block):
                return False
            previous_proof = previous_block['proof']
            proof = block['proof']
            hash_operation = hashlib.sha256(str(proof**2 - previous_proof**2).encode()).hexdigest()
            if hash_operation[:4] != '0000':
                return False
            previous_block = block
            block_index += 1
        return True
    
#    def add_transaction(self, sender, receiver, amount):
#        self.transactions.append({'sender': sender,
#                                  'receiver': receiver,
#                                  'amount': amount})
#        previous_block = self.get_previous_block()
#        return previous_block['index'] + 1
    
    def add_node(self, address):
        parsed_url = urlparse(address)
        self.nodes.add(parsed_url.netloc)
    
    def replace_chain(self):
        network = self.nodes
        longest_chain = None
        max_length = len(self.chain)
        for node in network:
            response = requests.get('http://127.0.0.1:5005/get_pkeys')
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


    def get_pkey(institution_id):
        print('running pkeys')
        payload = dict(iid='institution_id')
        response = requests.post('http://127.0.0.1:5005/get_institution_pkey', data=payload)
        if response.status_code == 200:
            print('running pkeys success')
            print(response)
  #          keylist = blockchain.parse_pkeys(response)
            return response
        else:
            print('running pkeys fail')
            return response
        

# Part 2 - Mining our Blockchain

# Creating a Web App
app = Flask(__name__)

# Creating an address for the node on Port 5000
node_address = str(uuid4()).replace('-', '')

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

    

# Mining a new block
#@app.route('/mine_block', methods = ['GET'])
#def mine_block():
#    previous_block = blockchain.get_previous_block()
#    previous_proof = previous_block['proof']
#    proof = blockchain.proof_of_work(previous_proof)
#    previous_hash = blockchain.hash(previous_block)
#    blockchain.add_transaction(sender = node_address, receiver = 'Hadelin', amount = 1)
#    block = blockchain.create_block(proof, previous_hash)
#    response = {'message': 'Congratulations, you just mined a block!',
#                'index': block['index'],
#                'timestamp': block['timestamp'],
#                'proof': block['proof'],
#                'previous_hash': block['previous_hash'],
#                'transactions': block['transactions']}
#    return jsonify(response), 200

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
    print(previous_block)
    print(previous_hash)
    data = {"previous_hash": previous_hash,
            'identifications': identifications,
            'institution_id': institution_id}
    sk = SigningKey.from_pem(open("private.pem").read())
    signature = sk.sign(json.dumps(data).encode())
    block = {'data': data,
             'signature': signature
            }
    open("block.json","w").write(str(block))
    response = {'message': 'blob.'}
    return jsonify(response), 200

# Running the app
app.run(host = '0.0.0.0', port = 5000)
