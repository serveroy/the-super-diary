import hashlib


def md5_hash(text):
    # Create an instance of the MD5 hash object
    md5 = hashlib.md5()
    # Convert the text to bytes (required by hashlib)
    text_bytes = text.encode('utf-8')
    # Update the hash object with the text bytes
    md5.update(text_bytes)
    # Generate the MD5 hash digest
    hash_digest = md5.hexdigest()
    return hash_digest
