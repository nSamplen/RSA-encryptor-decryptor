
from argparser import parser
import os
import asn1

from aesusage import *
from rsausage import *
from Cryptodome.Util.Padding import pad, unpad
from generatedRsaParams import e, p, q, n, f_n, d
import asnGenerator
#from aesusage import iv, key_size

keyLen = 32

def encryptFile(path):
    # Generate secret key
    key_s = os.urandom(keyLen)

    print('Key s = ', hex(int.from_bytes(key_s, "big")))
    #print('Plaintext:\n')
    #print(input)
    #iv = Random.new().read(AES.block_size)
    encryptedDataAES, iv  = AES_data_Encryption(path, key_s)
    
    #print('Encrypted AES data:\n')
    #print(encryptedDataAES)

    encryptedKey_S = RSA_data_Encryption(
        int.from_bytes(key_s, byteorder='big'), 
        int(e),
        int(n)
    )


    asnCodedText = asnGenerator.encode(
        n,
        e,
        encryptedKey_S,
        iv,
        len(encryptedDataAES),
        encryptedDataAES
    )

    output = open(path+'.ecrypted','wb')
    output.write(asnCodedText)
    output.close()

    #print('exp = ', e)
    #print('n = ', n)
    #print('d = ',d)


def decryptFile(path):
    #input = open(path,'rb').read()
    n_fromCipher, e_fromCipher, key_S_fromCipher, iv_fromCipher = asnGenerator.decode(path)
    #print('n = ', n_fromCipher)
    #print('e = ', e_fromCipher)
    #print('key_s = ', key_S_fromCipher)
   
    print('d = ', d)
    print('Enc Key s = ', key_S_fromCipher)
    decryptedKey_S = RSA_data_Decryption(
        key_S_fromCipher, 
        d,
        n_fromCipher
    )

    decryptedKey_S = decryptedKey_S.to_bytes(keyLen, 'big')
    print('Dec Key s = ', decryptedKey_S)

    with open('~tmp', 'rb') as file:
        data = file.read()
        #print('Cipher:\n')
        #print(data)
        print('Decrypted:\n')
        decryptedText = AES_data_Decryption(data, decryptedKey_S, iv_fromCipher)
            #pad(data,AES.block_size), decryptedKey_S, iv_fromCipher)
        decryptedText = unpad(decryptedText, AES.block_size)

    #print(decryptedText)
    os.remove('~tmp')

    output = open(path+'.decrypted','wb')
    output.write(decryptedText)
    output.close()

def addSignature(path):

    #input = open(path,'rb').read()
    sign_RSA = RSA_data_Sign(path, d, n)

    #signature = addSignatureRSA(path, int(d_sig, 16), int(n_sig, 16))

    encodedBytes = asnGenerator.encode_sign(n, d, sign_RSA)

    with open(path + '.sign', 'wb') as file:
        file.write(encodedBytes)
    
    return

def checkSignature(filePath, signPath):

    n_fromSign, Sign_fromSign = asnGenerator.decode_sign(signPath)
    #input = open(filePath,'rb').read()
    return RSA_data_CheckSign(
        Sign_fromSign, 
        e, 
        n_fromSign,
        filePath
        )

def main():

    args = parser.parse_args()
    
    if (args.enc):
        print("encrypt") 
        encryptFile(args.filepath)

    elif (args.dec):
        print("decrypt")
        decryptFile(args.filepath)

    elif (args.sgn):
        print("sighn") 
        addSignature(args.filepath)

    elif (args.chcksign):
        print("check sign")
        if checkSignature(args.filepath, args.sgnpath):
            print('Sign correct')
        else:
            print('Sign incorrect')

if __name__ == '__main__':
    main()