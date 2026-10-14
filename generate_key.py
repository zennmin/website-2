"""
generate_key.py
---------------
Run ONCE, locally:   python generate_key.py

Prints a PEM private key as a single line (newlines written as \\n) that you
paste into Render as the SERVER_PRIVATE_KEY_PEM environment variable.
Keep it secret and back it up: if it is lost, stored images cannot be decrypted.
"""
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
pem = key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
).decode()

print("Paste this value into Render -> Environment -> SERVER_PRIVATE_KEY_PEM:\n")
print(pem.strip().replace("\n", "\\n"))
