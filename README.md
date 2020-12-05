# RSA-encryptor-decryptor
RSA encryptor/decryptor + signing/verifing

## To Run:

### File Encryption
python kmzy1.py --enc --filePath your/path/...
The result is the file with the same name + ".encrypted"

### File Decryption
python kmzy1.py --dec --filePath your/path/...
The result is the file with the same name + ".decrypted"

### File Signing
python kmzy1.py --sgn --filePath your/path/...
The result is the file with the same name + ".sign"

### File Verifing
python kmzy1.py --chcksgn --filePath your/path/... --sgnPath your/path/to/sign/file...
The result is the output - "Sign correct" or "Sign incorrect"
