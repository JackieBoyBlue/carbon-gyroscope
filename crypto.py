from os import environ
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from hashlib import sha512
from base64 import b64decode, b64encode



# Generate key pair
# - - - - - - - - - - - WARNING - - - - - - - - - - - #
# Running this function risks overwritting existing keys
# Please pay attention to the save locations

def generate_key_pair(priv_pem_location:str='private.pem', pub_pem_location:str='public.pem'):
    # Generate key
    key = ECC.generate(curve='P-256')

    # Store the pems in files
    with open(priv_pem_location, 'wt') as f:
        f.write(key.export_key(format='PEM'))

    with open(pub_pem_location, 'wt') as f:
        f.write(key.public_key().export_key(format='PEM'))



# Make signature

def make_signature(message:bytes, priv_pem_location:str='.sensitive/private.pem') -> bytes:
    if environ.get('IN_DOCKER'): priv_pem_location = '/run/secrets/private_pem'
    key = ECC.import_key(open(priv_pem_location).read())
    h = SHA256.new(message)
    signer = DSS.new(key, mode='fips-186-3', encoding='der')
    signature = signer.sign(h)

    return b64encode(signature)



# Verify signature

def verify_signature(signature:bytes, message:bytes, pub_pem_location:str='.sensitive/public.pem'):
    if environ.get('IN_DOCKER'): pub_pem_location = '/run/secrets/public_pem'
    key = ECC.import_key(open(pub_pem_location).read())
    h = SHA256.new(message)
    verifier = DSS.new(key, mode='fips-186-3', encoding='der')
    try:
        verifier.verify(h, b64decode(signature))
        print("The message is authentic.")
    except ValueError:
        print("The message is not authentic.")



# Convert data to the required digest format

def make_digest(data:str) -> bytes:
    digest = sha512(data.encode('utf-8'))
    return b64encode(digest.digest())
