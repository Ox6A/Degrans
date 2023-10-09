import os
import pgpy
import warnings
from pgpy import PGPMessage
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm
from tkinter import filedialog
from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

privateKey = None
publicKey = None

def main():
    choice = input("What would you like to do?\n1. Encrypt a message 2. Decrypt a message 3. Exit ")
    if choice == "1":
        print("Please enter the location of the public key you would like to encrypt with: ")
        recPubFile = filedialog.askopenfilename()
        with open(recPubFile, "rb") as f:
            recPublicKey = pgpy.PGPKey.from_blob(f.read())[0]
        message = input("What would you like to say? ")
        encrypted = encrypt(message, recPublicKey)
        with open(os.getcwd()+"/encrypted.txt", "w") as f:
            f.write(encrypted)
        print("-"*len(welcomeMessage)+"\n")
        print(encrypted)
        print("-"*len(welcomeMessage))
        print(f"Saved to {os.getcwd()+'/encrypted.txt'}")
        print("-"*len(welcomeMessage)+"\n")
        main()
    if choice == "2":
        print("Please enter the location of the encrypted message you would like to decrypt: ")
        encFile = filedialog.askopenfilename()
        try:
            with open(encFile, "r") as f:
                message = f.read()
        except:
            print("Error loading file.")
            print("-"*len(welcomeMessage)+"\n")
            main()
        try:
            decrypted = decrypt(message, privateKey)
        except Exception as e:
            print(e)
            print("^^^ Error decrypting message.")
            print("-"*len(welcomeMessage)+"\n")
            main()
        print("-"*len(welcomeMessage))
        print(decrypted)
        print("-"*len(welcomeMessage)+"\n")
        main()
    if choice == "3":
        exit()
    else:
        print("Invalid choice, please try again.")
        main()
def loadPrimaryKeys(privFile):
    if not privFile:
        privFile = filedialog.askopenfilename()
    with open(privFile, "rb") as f:
        privateKey = pgpy.PGPKey.from_blob(f.read())[0]

    return privateKey

def genPrimaryKeys(password, name, email):
    key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 4096)
    uid = pgpy.PGPUID.new(name, email=email)
    key.add_uid(uid, usage={KeyFlags.Sign, KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
                hashes=[HashAlgorithm.SHA256, HashAlgorithm.SHA384, HashAlgorithm.SHA512, HashAlgorithm.SHA224],
                ciphers=[SymmetricKeyAlgorithm.AES256, SymmetricKeyAlgorithm.AES192, SymmetricKeyAlgorithm.AES128],
                compression=[CompressionAlgorithm.ZLIB, CompressionAlgorithm.BZ2, CompressionAlgorithm.ZIP, CompressionAlgorithm.Uncompressed])
    key.protect(password, SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)
    privateKey = key
    publicKey = key.pubkey

    dir = filedialog.askdirectory()
    dirPriv = dir+"/"+str(name.replace(" ", "_"))+"_"+"privateKey.asc"
    dirPub = dir+"/"+str(name.replace(" ", "_"))+"_"+"publicKey.asc"
    with open(dirPriv, "w+b") as f:
        f.write(bytes(privateKey))
    with open(dirPub, "w+b") as f:
        f.write(bytes(publicKey))

    return privateKey

def encrypt(message, public):
    message = PGPMessage.new(message)
    encrypted = public.encrypt(message)
    return str(encrypted)

def decrypt(message, private):
    encrypted_message = PGPMessage.from_blob(message)
    decrypted = privateKey.decrypt(encrypted_message).message
    return str(decrypted)

welcomeMessage = "Hello! Welcome to the PGP Encryption/Decryption Tool! Please select an option below to begin."
print("-"*len(welcomeMessage))
print(welcomeMessage)
choice = input("1. Generate Primary Keys or 2. Load Primary Keys: ")
print("-"*len(welcomeMessage))
if choice == "1":
    name = input("Enter your full name: ")
    name = name.lower()
    email = input("Enter your email address: ")
    email = name.lower()
    password = input("Enter a password to protect your keys: ")
    print("Please select a location to store your keys:")
    privateKey = genPrimaryKeys(password, name, email)
    print("-"*len(welcomeMessage))
    print("Your keys have been generated and stored in the specified location.")
    print("-"*len(welcomeMessage))
    main()
if choice == "2":
    print("Please select the location of your PRIVATE key:")
    privFile = filedialog.askopenfilename()
    if loadPrimaryKeys(privFile):
        privateKey = loadPrimaryKeys(privFile)
        if privateKey.is_public:
                print("\n**********\nError loading private key. Please select a PRIVATE key.\n**********\n")
                exit()
        password = input("Keys Loaded, please enter your password to unlock your private key: ")
        try:
            with privateKey.unlock(password):
                assert privateKey.is_unlocked
                print("Private Key Unlocked.")
                print("-"*len(welcomeMessage))
                main()
        except Exception as e:
            print("\n**********\nError unlocking private key. Possbile incorrect password?\n**********\n")
            print(e)
            exit()
    else:
        print("Error loading keys.")
        exit()
    print("-"*len(welcomeMessage))
