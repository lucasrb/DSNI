# DSNI
Decentralized Student National Identification - A blockchain based application for student identification
@Author: Lucas de Souza Ribeiro

# This code has been inicialized under the Udemy Course "Blockchain A-Z™: Learn How To Build Your First Blockchain"
# Credits to the Authors: Hadelin de Ponteves and Kirill Eremenko from SuperDataScience
# Made in Python using the following libraries
# ecdsa - http://github.com/warner/python-ecdsa
# flask - http://flask.pocoo.org/
# requests - http://python-requests.org

Using the base implementation, the block has been changed to register Student Identification
by Institutions while maintaining the security to history whoever submits the block
Created by Lucas Ribeiro, as a work for bachelor degree completion.
For its multidisciplinary comprehensiveness and size, the work is only a part of the desired release.

Under the circustance of needing to spread public keys from every institution, another blockchain has been created
to communicate with the first one, and secure that every key can also be maintained in a secure structure

In a hypothetical release:
The DSNI Blockchain could only communicate to his local Public Key Blockchain for get requests

Public Key Blockchain can only accept blocks which can be validated with its own registered public keys
(This creates a need for another institution to take part when adding new institutions to the system)

DSNI Blockchain can only accept blocks which can be validated directly using the institution public key on the PKey Blockchain
Which is found by its institution code
(This creates a need for a list probably under the Ministery of Education to identify each possible institution under a different number)

Connections to other nodes are currently via post input (Nothing really changed from the base version)

(WIP)
This code is based in a Proof of Work implementation, the nodes only checks for the longest chain.
When changing the rule to accept blocks to use a Proof of Authority, some flaws were identified, as a single node could infinitely 
create blocks and later replace the whole system with his own blockchain.

A batch request for verification could also be usefull for entertainment industry, as they could check a full list of IDs without 
flooding the network with multiple requests.

Optimization of this system has not been evaluated yet, the hypothetical release to use every university of Brazil as a node
creating around 2.000 nodes to communicate to each other, and responding to get requests having to iterate trough the chain
as its the only secure way to guarantee that the information is secured by the blockchain structure, also thinking about 
a balanced distribution of external requests, looking for proximity, power of computation and traffic control.
Some security measures should also be applied, as request limitation per second per IP, and other denial of service protections.


