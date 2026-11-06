from Crypto.Cipher import ChaCha20
import os


# both have 22 chars
P1 = b"this is plain text one"
P2 = b"this is plain text two"

key = os.urandom(32)
nonce = os.urandom(12)


cipher1 = ChaCha20.new(key=key, nonce=nonce)
C1 = cipher1.encrypt(P1)

# if we use the same cipher object for both texts, it will cause problem because of
# going forward in keystream and not using the same part for both texts
cipher2 = ChaCha20.new(key=key, nonce=nonce)
C2 = cipher2.encrypt(P2)



def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

X1 = xor_bytes(P1, P2)
X2 = xor_bytes(C1, C2)


print("P1 XOR P2:")
print(X1.hex())

print("C1 XOR C2:")
print(X2.hex())

# we will get same number because:
# c1 ^ c2 = (p1 ^ ks) ^ (p2 ^ ks) = (p1 ^ p2) ^ (ks ^ ks) = (p1 ^ p2) ^ (0) = p1 ^ p2  
print("result of compare:", X1 == X2)


print("\nrecovering p2 when we have p1:")
# we know: c1 ^ c2 = p1 ^ p2 so we can get p2 : c1 ^ c2 ^ p1 = p2
# Attacker knows P1, C1 and C2
recovered_P2 = xor_bytes( X2, P1)

print("Original P2: ", P2.decode())
print("Recovered P2:", recovered_P2.decode())

print("recovery result: ", recovered_P2 == P2)


print("\nusing different nonces for keystream (same key)")
nonce1 = os.urandom(12)
nonce2 = os.urandom(12)

cipher1 = ChaCha20.new(key=key, nonce=nonce1)
cipher2 = ChaCha20.new(key=key, nonce=nonce2)

C1_new = cipher1.encrypt(P1)
C2_new = cipher2.encrypt(P2)


cipher_xor_new = xor_bytes(C1_new, C2_new)


recovered_P2_new = xor_bytes(cipher_xor_new, P1)


print("P1 XOR P2:", X1.hex())
print("C1 XOR C2:", cipher_xor_new.hex())


print("Original P2: ", P2.decode())
print("Recovered P2:", recovered_P2_new.decode(errors="replace"))

print("recovery result:", recovered_P2_new == P2)