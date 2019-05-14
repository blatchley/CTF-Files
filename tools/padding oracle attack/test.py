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
# a = b'\xdf@\xf4\xf1[\x9e\xa1\x16\xde\xe8\xa8\xb8U\x92\xd0\x0c\xfb`\x1d\x0e\xbe\x167\xb5\xcb#\xd7\xdbE\x99\xa5\xa4bMf\xf3\x8cQy3\xae\x07\xfd*\xe6]G\x92'
# print(a.hex())
inputstring = "f90b43afd31b037bc5b81371bd86d6aaf6523c146bab6f356f29e94e2d8391500c82fff0b2b774ec5d2aeda5f6c05c6be3f045e7c6afbfc52351752e1422f8c1"
inputbytes = bytes.fromhex(inputstring)
print(inputbytes)
print(attack(inputbytes))