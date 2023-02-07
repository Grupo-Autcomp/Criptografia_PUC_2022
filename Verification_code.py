from ecdsa import ECDH, SigningKey, VerifyingKey, NIST256p
from hashlib import sha256
from cryptography.fernet import Fernet
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os



def verification(pub, sig, msg):
    try: 
        vk = VerifyingKey.from_string(bytes.fromhex(pub), curve=NIST256p, hashfunc=sha256)
        
        if(vk.verify(bytes.fromhex(sig), msg.encode())):
            #print("VERIFICADO")
            return True
    except:
        #print("NÃO VERIFICADO")
        return False

def generation(msg):
    sk = SigningKey.generate(curve=NIST256p, hashfunc=sha256)
    pri = str(sk.to_string().hex())
    pub = str(sk.verifying_key.to_string().hex())
    sig = str(sk.sign(msg.encode()).hex())
    return pri, pub, sig

def hash_calculation(msg):
    has = sha256(msg.encode()).hexdigest()
    return has

def ecdh(pri, remote_public_key):
    ecdh = ECDH(curve=NIST256p)
    ecdh.load_private_key_bytes(bytes.fromhex(pri))
    local_public_key = ecdh.get_public_key()
    ecdh.load_received_public_key_bytes(bytes.fromhex(remote_public_key))
    secret = str(ecdh.generate_sharedsecret_bytes().hex())
    return secret


def encrypt_aes128(msg, key):
    
    if key=='':
        key = os.urandom(16).hex()
        cipher = AES.new(bytes.fromhex(key), AES.MODE_ECB)
        ciphertext = cipher.encrypt(pad(msg.encode("utf8"), 16))
        #key = key.decode()

    else:
        #key = key.encode()
        cipher = AES.new(bytes.fromhex(key), AES.MODE_ECB)
        ciphertext = cipher.encrypt(pad(msg.encode("utf8"), 16))
        #key = key.decode()
        
    return key, ciphertext.hex()

def decrypt_aes128(msg, key):
    
    msg = bytes.fromhex(msg)
    cipher = AES.new(bytes.fromhex(key), AES.MODE_ECB)
    plaintext = cipher.decrypt(msg)
    plaintext = unpad(plaintext, 16).decode()

    return plaintext
    


    
if __name__ == "__main__":
    
    pub = 'fba56058d8a16f61947bfd24cae977e200f5af631ec399bd617e5d9554075a232dff13057c0b8d5aa98b59c54542a31a18734fa67811f457f2ab5c4d50683324'
    sig = '83498FD7A8EA8CCBBA7C3AEB402DEF20CBC78CA04DFA0C99E5A3AE8B1D9D78192A64FFDF9F103C60E62F9EC477BB9EBE9B08589E87CF1072173F261FC75EEAD8'
    msg = 'oi, blz?'
    
    pri, pub, sig = generation(msg)
    verification(pub, sig, msg)
      
    hash_calculation(msg)
    
    ecdh(pri, pub)

    key, cipher = encrypt_aes128(msg, '341E78DBC846443C92CA7D2CD004B0C0')

    print(f"""
          
          {cipher}
          {len(cipher)}
          
          {key}
          {len(key)}
          """)
          
    key = '341E78DBC846443C92CA7D2CD004B0C0'
    #cipher = 'B04D64E7ED662F4272F599A828DA50FC'
    
    text = decrypt_aes128(cipher, key)

    print(f"""
          {text.decode()}
          {len(text)}
          
          """)
    #print(pub)
    #print(sig)
    #print(msg)
   
    #print(type(pub))
    #print(type(sig))
    #print(type(msg))