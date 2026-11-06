from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
import os

#creating 2048 bit rsa key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()


#messages with different lengthes
messages = [
    os.urandom(50),
    os.urandom(190),
    os.urandom(191),
    os.urandom(300)
]

for m in messages:
    try:
        ciphertext = public_key.encrypt(
            m,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print(f"Message with {len(m)} bytes is ok")

    except ValueError:
        print(f"Message with {len(m)} bytes not accepted")




print("\nencrypting same medssage twice with public key:")

message = b"message for encrypt"

ciphertext1 = public_key.encrypt(
    message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

ciphertext2 = public_key.encrypt(
    message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

print("\nCiphertext 1:", ciphertext1.hex())
print("\nCiphertext 2:", ciphertext2.hex())
print("\nsame result:", ciphertext1 == ciphertext2)



print("\ndecrypting an encrypted message with private key:")

decrypted_message = private_key.decrypt(
    ciphertext1,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

print("Original message: ", message.decode())
print("Decrypted message:", decrypted_message.decode())

print("Decryption result:", decrypted_message == message)
