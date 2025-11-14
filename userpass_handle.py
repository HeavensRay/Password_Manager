
# verifies password and handles key genfrom argon2.low_level 
from argon2.low_level import hash_secret_raw, hash_secret, Type
from argon2 import PasswordHasher
from Crypto.Random import get_random_bytes
import binascii
# dek in sql w dek iv, kek iv, Argon2id salt, vault data

# flow:
# master paassword => argon2id(MP, salt , etc) => KEK , encrypt/decrypt DEK(kek, VaultIv) => encrypt/decrypt vault,

#argon 2id generate KDF

# official docs :) ""

# KEK from argon generate
def argon_KDF(password, salt):
    '''Generates KDF this IS a secret. Salt is in db though'''
    argon_KDF = hash_secret_raw(   # raw for kek, encoded for verification low level for kek
        secret=password,
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        type=Type.ID
    ) 
    return argon_KDF

def public_key(password):
    '''Generates encoded authentication key. Goes on database for all to see'''
    ph = PasswordHasher()
    encoded_safe = ph.hash(password=password)
    return encoded_safe

def verify_master(password, db_hash):
    '''Get key from database and verify wether password is correct '''

    ph = PasswordHasher()
    ph.verify(db_hash, password)


