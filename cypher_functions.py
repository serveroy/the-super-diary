# cypher functions

def encrypt(message, key):
    """
    The encryption function.
    :param message: the message to encrypt.
    :param key: the shared key for the client and the server.
    :return:
    """
    # the encryption function
    message_bytes = message.encode('utf-8')
    key_bytes = key.encode('utf-8')

    # zero-pad message and key to the same length
    max_len = max(len(message_bytes), len(key_bytes))
    message_bytes = message_bytes.ljust(max_len, b'\x00')
    key_bytes = key_bytes.ljust(max_len, b'\x00')

    ciphertext = bytes([message_byte ^ key_byte for message_byte, key_byte in zip(message_bytes, key_bytes)])
    return ciphertext


def decrypt(ciphertext, key):
    """
    The decryption function.
    :param ciphertext: the cypher to decrypt.
    :param key: the shared key for the client and the server.
    :return:
    """
    # the decryption function
    key_bytes = key.encode('utf-8')

    # zero-pad key to the same length as ciphertext
    key_bytes = key_bytes.ljust(len(ciphertext), b'\x00')

    plaintext_bytes = bytes([c ^ k for c, k in zip(ciphertext, key_bytes)])

    # remove zero-padding from plaintext
    plaintext_bytes = plaintext_bytes.rstrip(b'\x00')

    plaintext = plaintext_bytes.decode('utf-8')
    return plaintext



