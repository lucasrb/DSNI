# -*- coding: utf-8 -*-
"""
Created on Thu Nov 29 20:33:21 2018

@author: Lucas-PC
"""

from ecdsa import SigningKey, NIST256p, BadSignatureError, VerifyingKey
sk = SigningKey.generate(curve=NIST256p)
vk = sk.get_verifying_key()


message = "message".encode('utf-8')
sig = sk.sign(message)


open("private.pem","wb").write(sk.to_pem())
open("public.pem","wb").write(vk.to_pem())



vk = VerifyingKey.from_pem(open("public.pem").read())
try:
    vk.verify(sig, message)
    print("good signature")
except BadSignatureError:
    print("BAD SIGNATURE")

'''
print(vk)
open("private.txt","wb").write(sk_string)
open("public.txt","wb").write(vk.to_string())
verif_key = VerifyingKey.from_string(open("public.txt","rb").read())
print(open("public.txt","rb").read())
#verif_key = VerifyingKey.from_string("0x00000230C15B14E0", curve=NIST256p)
try:
    vk.verify(sig, "message".encode('utf-8'))
    print("good signature")
except BadSignatureError:
    print("BAD SIGNATURE")
'''


'''
print(sk)
vk = sk.get_verifying_key()
print(vk)
message = "messagen".encode('utf-8')
signature = sk.sign("message".encode('utf-8'))
print(signature)

try:
    vk.verify(signature, message)
    print("good signature")
except BadSignatureError:
    print("BAD SIGNATURE")

assert vk.verify(signature, "message".encode('utf-8'))
'''