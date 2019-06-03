from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hmac, hashes
from cryptography.exceptions import InvalidSignature

from os import urandom, path

from handlers import cd

'''
    This module AES encrypts files with CBC mode.
'''

# Debug flag for testing purposes
DEBUG = False

IV_SIZE = 16
KEY_LENGTH = 32
PADDING_BLOCK_SIZE = 128
BACKEND = default_backend()

def myEncrypt(message, key):
    '''
        Encrypt data with a given key.
    '''
    if len(key) < KEY_LENGTH:
        raise Exception("Key length must be at least 32.")

    # Generate random 16 Bytes
    IV = urandom(IV_SIZE)

    # Initialize encryption object
    cipher = Cipher(algorithms.AES(key), modes.CBC(IV), backend=BACKEND)
    encryptor = cipher.encryptor()

    # Initialize padding object
    padder = padding.PKCS7(PADDING_BLOCK_SIZE).padder()

    # Append padding to message and close padding object
    p_message = padder.update(message) + padder.finalize()

    # Encrypt the padded message and close encryption object
    C = encryptor.update(p_message) + encryptor.finalize()

    return (C, IV)


def myFileEncrypt(filename, klength=KEY_LENGTH):
    '''
        Encrypt a file with a randomly generated 32-bit key.
    '''

    # Open image file and save the bytes
    with open(filename, 'rb') as f:
        print('Reading file...')
        content = b''.join(f.readlines())

    # Get file extension
    ext = path.splitext(filename)[1]

    # Generate random key
    key = urandom(klength)

    # Encrypt the contents of the file
    C, IV = myEncrypt(content, key)

    return (C, IV, key, ext)

def myDecrypt(encrypted_message, key, IV):
    '''
        Decrypt data with a given key
    '''

    # Initialize decryption object
    cipher = Cipher(algorithms.AES(key), modes.CBC(IV), backend=BACKEND)
    decryptor = cipher.decryptor()

    # Decrypt the encrypted message
    decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()

    # Initialize unpadding object
    unpadder = padding.PKCS7(128).unpadder()

    # Unpad the decrypted message
    M = unpadder.update(decrypted_message) + unpadder.finalize()

    return M

def myFileDecrypt(filename, key, IV):
    '''
        Decrypt a file with a given key.
    '''
    # Open encrypted file and save the bytes
    with open(filename, 'rb') as f:
        print('Reading file...')
        C = b''.join(f.readlines())

    # Decrypt bytes
    result = myDecrypt(C, key, IV)

    return result

def myEncryptMAC(message, encKey, HMACKey):
    '''
        Encrypt data with an HMAC tag for verification.
    '''

    # Encrypt data
    C, IV = myEncrypt(message, encKey)
    
    # Create HMAC object with encrypted data as input
    h = hmac.HMAC(HMACKey, hashes.SHA256(), backend=BACKEND)
    h.update(C)
    
    # Generate the tag by closing the hashing object
    tag = h.finalize()

    return (C, IV, tag)

def myFileEncryptMAC(filename, klength=KEY_LENGTH):
    '''
        Encrypt a file with HMAC verification.
    '''

    # Open image file and save the bytes
    with open(filename, 'rb') as f:
        print('Reading file...')
        content = b''.join(f.readlines())

    # Get file extension
    ext = path.splitext(filename)[1]

    # Generate random key
    encKey = urandom(klength)

    # Generate random HMAC key
    HMACKey = urandom(klength)

    # Encrypt the contents of the file
    C, IV, tag = myEncryptMAC(content, encKey, HMACKey)

    return (C, IV, tag, encKey, HMACKey, ext)

def myFileDecryptMAC(filename, encKey, HMACKey, IV, tag):
    '''
        Decrypt a file with a given key.
    '''
    # Open encrypted file and save the bytes
    with open(filename, 'rb') as f:
        print('Reading file...')
        C = b''.join(f.readlines())

    if DEBUG:
        # Purposefully deprecate data for testing purposes
        C += b'Append junk to test invalid data'

    # Create HMAC object
    h = hmac.HMAC(HMACKey, hashes.SHA256(), backend=BACKEND)
    h.update(C)

    # Verify the data with the HMAC tag
    try:
        h.verify(tag)
    except InvalidSignature as e:
        # Notify user and exit program if verification fails
        print('Encrypted data was not valid.')
        exit(1) 

    # Decrypt bytes
    result = myDecrypt(C, encKey, IV)

    return result

def main():

    # Paths to input and output folders
    INPUT_DIR = 'input'
    OUTPUT_DIR = 'output'

    # Sample image file
    filename = 'smile.jpg'

    # Encrypt the file
    C, IV, tag, encKey, HMACKey, ext = myFileEncryptMAC(f'{INPUT_DIR}/{filename}')

    # Save the encrypted file
    with open(f'{OUTPUT_DIR}/encrypted_file{ext}', 'wb') as f:
        print('Saving encrypted file...')
        f.write(C)

    # Decrypt file
    M = myFileDecryptMAC(f'{OUTPUT_DIR}/encrypted_file{ext}', encKey, HMACKey, IV, tag)

    # Save decrypted file
    with open(f'{OUTPUT_DIR}/decrypted_file{ext}', 'wb') as f:
        print('Saving decrypted file...')
        f.write(M)

    print('Done.')


if __name__ == '__main__':
    main()
