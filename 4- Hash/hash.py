import hashlib
import hmac
import json
import os


transaction = {
    "transaction_id": "TX1024",
    "amount": 500000,
    "status": "success"
}

# shared secret key
secret_key = os.urandom(12)


# fixed format
def serialize_message(message):
    return json.dumps(
        message,
        sort_keys=True,
        separators=(",", ":")
    ).encode("utf-8")



print("\nchanging amount and hash:")

original_message = serialize_message(transaction)
original_hash = hashlib.sha256(original_message).hexdigest()

print("\nOriginal message:", original_message.decode())
print("Original SHA256:", original_hash)


# changing the amount and making new hash for it
modified_transaction = transaction.copy()
modified_transaction["amount"] = 10000

modified_message = serialize_message(modified_transaction)
modified_hash = hashlib.sha256(modified_message).hexdigest()

print("\nModified message:", modified_message.decode())
print("Modified SHA256:", modified_hash)

# Store verifies the modified message and hash and get same hash
print("\nSHA256 verification:", hashlib.sha256(modified_message).hexdigest() == modified_hash)




print("\nusing HMAC instead of simple hash:")

original_hmac = hmac.new(
                    secret_key,
                    original_message,
                    hashlib.sha256
                ).hexdigest()

print("Original HMAC:", original_hmac)




print("\nchanging the transaction amount with original HMAC:")

tampered_transaction = transaction.copy()
tampered_transaction["amount"] = 600000
tampered_message = serialize_message(tampered_transaction)

def verify_hmac(message, received_hmac, secret_key):
    calculated_hmac = hmac.new(
                                secret_key,
                                message,
                                hashlib.sha256
                            ).hexdigest()
    return hmac.compare_digest(
        calculated_hmac,
        received_hmac
    )

# using the original HMAC 
verification = verify_hmac(
    tampered_message,
    original_hmac,
    secret_key
)

print("Original transaction:", transaction)
print("Modified transaction:", tampered_transaction)
print("HMAC verification:", verification)



print("\nsending same message again with same hmac:")


replay_verification = verify_hmac(
    original_message,
    original_hmac,
    secret_key
)

print("HMAC verification:", replay_verification)
