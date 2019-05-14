verbose = True

def attack(message):
    reconstructed = b''
    while len(message) >= 32:
        # retrieved block
        block = [0] * 16
        # byte in block
        for i in range(1, 17):
            # PKCS#7 padding
            pad = [0] * (16 - i) + [i] * i
            for x in range(256):
                # tested byte
                block[-i] = x
                if x == i:
                    continue
                
                # alter message
                test = bytearray(message)
                for j in range(16):
                    test[-32 + j] ^= block[j] ^ pad[j]
                test = bytes(test)
                responsecode = oracle(test)
                if responsecode == 200:
                    break
                if responsecode == 500:
                    pass
            else:
                block[-i] = i
        # store retrieved block and continue
        reconstructed = bytes(block) + reconstructed
        message = message[:-16]
    return reconstructed

from Crypto import Random
from Crypto.Cipher import AES
import requests


def oracle(message):
    if verbose:
        print("message is")
    messagestring = message.hex()
    if verbose:
        print(messagestring)
    payload = {'flag': messagestring}
    r = requests.post("http://165.22.90.215:8083/getflag", data=payload)
    if verbose:
        print(r.status_code)
        print(r.text)

    return r.status_code

inputstring = "2d00c696765ee44e54225a43b18126160b278ba99a45a58681444a02d01933881cb35ea63cd64837fa70dc3b77bef33181289de11317f3a5d8350b2c150c14f8"
inputbytes = bytes.fromhex(inputstring)
print(inputbytes)
print(attack(inputbytes))