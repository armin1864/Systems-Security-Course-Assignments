from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization


alice_private = X25519PrivateKey.generate()
alice_public = alice_private.public_key()

bob_private = X25519PrivateKey.generate()
bob_public = bob_private.public_key()


alice_bob_shared = alice_private.exchange(bob_public)
bob_alice_shared = bob_private.exchange(alice_public)


print("shared secrets between alice and bob:")
print("Alice shared secret:", alice_bob_shared.hex())
print("Bob shared secret:  ", bob_alice_shared.hex())
print("same secret?", alice_bob_shared == bob_alice_shared)



print("\n------exchanging with mallory in the middle------")

mallory_private = X25519PrivateKey.generate()
mallory_public = mallory_private.public_key()

# middle man attack:
alice_mallory_shared = alice_private.exchange(mallory_public)
mallory_alice_shared = mallory_private.exchange(alice_public)


bob_mallory_shared = bob_private.exchange(mallory_public)
mallory_bob_shared = mallory_private.exchange(bob_public)


print("\nAlice shared secret: ", alice_mallory_shared.hex())
print("Bob shared secret:   ", bob_mallory_shared.hex())

print("\nMallory with Alice secret:", mallory_alice_shared.hex())
print("Mallory with Bob secret:  ", mallory_bob_shared.hex())



print("\nAlice and Mallory have equal secret?",alice_mallory_shared == mallory_alice_shared)
print("Alice and Mallory have equal secret?",bob_mallory_shared == mallory_bob_shared)
print("Alice and Mallory have equal secret?",alice_mallory_shared == bob_mallory_shared)
