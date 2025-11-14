from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

    # return decrypted text

def encrypt_DEK(KEK_Key,DEK_plaintext): 
    '''Encrypt w KEK '''
    nonce = get_random_bytes(12)
    cipher_kek_enc = AES.new(key=KEK_Key, mode=AES.MODE_GCM, nonce=nonce) # cipher operation
    ciphertext, tag = cipher_kek_enc.encrypt_and_digest(DEK_plaintext) # tag ensures data is correctt 
    return ciphertext, tag ,nonce # tag ensures data is correctt 


def decrypt_DEK(KEK_Key, ciphertext, tag, nonce):
    '''Decrypt w KEK '''
    cipher_kek_dec = AES.new(key=KEK_Key, mode= AES.MODE_GCM, nonce=nonce)
    dek_decrypt = cipher_kek_dec.decrypt_and_verify(ciphertext, tag) 
    return dek_decrypt

