# Python program to implement ECC encryption and decryption on any binary file like image, video, audio, etc.
import mmap
import secrets
from tinyec import registry, ec
from Crypto.Cipher import AES
import hashlib, secrets, binascii, os

class Key:
    '''
    This class is used to generate public and private key
    '''
    def __init__(self) -> None:
        '''
        This constructor function initializes the curve.
        It uses secp256r1 by default
        '''
        self.curve = registry.get_curve('secp256r1')    # Initializes the curve
        self.privateKey = secrets.randbelow(self.curve.field.n)    # Initializes private key
        self.publicKey = self.privateKey * self.curve.g       # Initializes public key
        self.cipherTextPrivateKey = None    # For Decryption (Keep private)
        self.cipherTextPublicKey = None    # For Encryption (Give to other person)
    
    def generate_encryption_key(self):
        '''
        This function generates encryption key
        '''
        self.cipherTextPrivateKey = secrets.randbelow(self.curve.field.n)
        return self.cipherTextPrivateKey
    
    def compress_point(self, point):
        '''
        Compresses the point
        Converts the given point from Integer Value to Hexadecimal Value
        '''
        compressed_point = (hex(point.x), hex(point.y))
        return compressed_point


class ECC:
    '''
    This class is used to encrypt/decrypt the data
    '''
    def __init__(self):
        self.curve = registry.get_curve('secp256r1')

    def encrypt_AES_GCM(self, msg, secretKey):
        '''
        The ciphertext is obtained by the symmetric AES-GCM encryption, along with the nonce (random AES initialization vector) and authTag (the MAC code of the encrypted text, obtained by the GCM block mode).
        '''
        aesCipher = AES.new(secretKey, AES.MODE_GCM)
        ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
        return (ciphertext, aesCipher.nonce, authTag)

    def decrypt_AES_GCM(self, ciphertext, nonce, authTag, secretKey):
        '''
        To decrypt the encrypted message, we use the data produced during the encryption { ciphertext, nonce, authTag, cipherTextPublicKey }, along with the decryption privateKey. 
        The result is the decrypted plaintext message. 
        We use authenticated encryption (GCM block mode), so if the decryption key or some other parameter is incorrect, the decryption will fail with an exception.
        '''
        aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
        plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
        return plaintext

    def ecc_point_to_256_bit_key(self, point):
        sha = hashlib.sha256(int.to_bytes(point.x, 32, 'big'))
        sha.update(int.to_bytes(point.y, 32, 'big'))
        return sha.digest()

    def encrypt_ECC(self, msg, publicKey, cipherTextPrivateKey):
        sharedECCKey = cipherTextPrivateKey * publicKey
        secretKey = self.ecc_point_to_256_bit_key(sharedECCKey)
        ciphertext, nonce, authTag = self.encrypt_AES_GCM(msg, secretKey)
        cipherTextPublicKey = cipherTextPrivateKey * self.curve.g
        return (ciphertext, nonce, authTag, cipherTextPublicKey)

    def decrypt_ECC(self, encrypted, privateKey, e, msgType=0):   # 0 for file, 1 for string
        if(msgType):
            (ciphertext, nonce, authTag, cipherTextPublicKey) = encrypted
        else:
            with open(encrypted, 'rb') as f:
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data:
                    enc_msg = data.read()
                    content = enc_msg.split(b'<|END|>\n')
                    cipherTextPublicKey = content[0].decode("utf-8").split(":")
                    cipherTextPublicKey = ec.Point(e.curve, 
                                                   int(cipherTextPublicKey[0]), 
                                                   int(cipherTextPublicKey[1]))
                    ciphertext = content[1].strip()
                    nonce = content[2].strip()
                    authTag = content[3].strip()
        sharedECCKey = privateKey * cipherTextPublicKey
        secretKey = self.ecc_point_to_256_bit_key(sharedECCKey)
        plaintext = self.decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey)
        return plaintext


class Run:
    def __init__(self):
        pass

    def help(self):
        print(f'''
        0. Exit
        1. Generate/Regenerate Keys
        2. Encrypt Message
        3. Decrypt Message
        99. Help Menu
        ''')

    def printEncryptedMsgObj(self, obj):
        for i, j in obj.items():
            print(i, ":", j)

if __name__ == '__main__':
    r = Run()

    r.help()
    encryptedMsg = None
    decryptedMsg = None
    
    try:
        while(user_input:= input(">>> ")):
            try:
                user_input = int(user_input)
            except ValueError as e:
                print("Invalid Input")
                user_input = 99

            if(user_input == 0):
                break;

            if(user_input == 1):
                k = Key()
                privateKey = k.privateKey
                publicKey = k.publicKey
                print(f'''Keys:
                Public Key: {str(publicKey.x)},{str(publicKey.y)}
                Private Key: {privateKey}
                    ''')

            elif(user_input == 2):
                e = ECC()
                k = Key()
                cipherTextPrivateKey = k.generate_encryption_key()

                path = input("Enter file path to be encrypted: ")
                if(not os.path.isfile(path)):
                    print("File not found")
                    continue

                pubKey = input("Enter Public Key: ").split(",")
                with open(path, "rb") as f:
                    with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as msg:
                        try:
                            encryptedMsg = e.encrypt_ECC(msg.read(), ec.Point(e.curve, int(pubKey[0]), int(pubKey[1])), cipherTextPrivateKey)
                        except Exception as e:
                            print("Invalid Public Key")
                            continue
                        
                
                encryptedMsgObj = {
                    'ciphertext': binascii.hexlify(encryptedMsg[0]).decode("ASCII"),
                    'nonce': binascii.hexlify(encryptedMsg[1]).decode("ASCII"),
                    'authTag': binascii.hexlify(encryptedMsg[2]).decode("ASCII"),
                    'cipherTextPublicKey': hex(encryptedMsg[3].x) + hex(encryptedMsg[3].y % 2)[2:]
                }
                print("Message Encrypted Successfully!!!")

                while(True):
                    encryptedMsgFilePath = input("Path to save encrypted message: ")
                    if(os.path.isfile(encryptedMsgFilePath)):
                        cont = input("File already exists. Do you want to overwrite? (y/N): ").lower()
                        if(cont != 'y'):
                            continue
                    break

                with open(encryptedMsgFilePath, 'wb') as f:
                    f.seek((len(encryptedMsg[0]) + len(encryptedMsg[1]) + len(encryptedMsg[2]) + len(str(encryptedMsg[3].x)) + len(str(encryptedMsg[3].y))) + 28 - 1)
                    f.write(b'\0')

                with open(encryptedMsgFilePath, 'r+b') as f:
                    with mmap.mmap(f.fileno(), os.path.getsize(encryptedMsgFilePath), access=mmap.ACCESS_WRITE) as m:
                        m.seek(0)
                        m.write(str(str(encryptedMsg[3].x) + ":" + str(encryptedMsg[3].y)).encode("utf-8") + os.linesep.encode("utf-8") + "<|END|>".encode("utf-8") + os.linesep.encode("utf-8"))
                        m.write(encryptedMsg[0] + os.linesep.encode("utf-8") + "<|END|>".encode("utf-8") + os.linesep.encode("utf-8"))
                        m.write(encryptedMsg[1] + os.linesep.encode("utf-8") + "<|END|>".encode("utf-8") + os.linesep.encode("utf-8"))
                        m.write(encryptedMsg[2])
                        m.close()

                del encryptedMsg

            elif(user_input == 3):
                e = ECC()
                try:
                    privKey = int(input("Enter Private Key: "))
                except ValueError:
                    print("Invalid Private Key")
                    continue

                encryptedMsgFilePath = input("Path to encrypted message: ")
                if(not os.path.isfile(encryptedMsgFilePath)):
                    print("File not found")
                    continue

                # decryptedMsg = e.decrypt_ECC(encryptedMsgFilePath, privKey, e)
                try:
                    decryptedMsg = e.decrypt_ECC(encryptedMsgFilePath, privKey, e)
                except ValueError as e:
                    print(e)
                    print("Invalid Private Key or Input File")
                    continue

                while(True):
                    path = input("Filename to Save decrypted message: ")
                    if(os.path.isfile(path)):
                        cont = input("File already exists. Do you want to overwrite? (y/N): ").lower()
                        if(cont != 'y'):
                            continue
                    break

                with open(path, 'wb') as f:
                    f.seek(len(decryptedMsg) - 1)
                    f.write(b'\0')
                
                with open(path, 'r+b') as f:
                    with mmap.mmap(f.fileno(), os.path.getsize(path), access=mmap.ACCESS_WRITE) as m:
                        m.seek(0)
                        m.write(decryptedMsg)
                # decryptedMsg = None     # Clearing decryptedMsg to consume less memory
                del decryptedMsg

            # elif(user_input == 4):
            #     print("Encrypted Message:", encryptedMsg)

            # elif(user_input == 5):
            #     print("Decrypted Message:", decryptedMsg)

            elif(user_input == 99):
                r.help()

            else:
                print("Invalid Option...")
    except KeyboardInterrupt:
        print("\nExiting...")