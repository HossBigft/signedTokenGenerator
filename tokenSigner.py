import base64
import time
import secrets
import os
import sys
import json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.backends import default_backend

KEY_PATH = "ed25519_private.pem"
PUBKEY_PATH = "pub.key" 

def load_or_generate_key():
    if os.path.exists(KEY_PATH):
        # Load existing private key
        with open(KEY_PATH, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
        print("Using existing private key.")
    else:
        private_key = Ed25519PrivateKey.generate()
        with open(KEY_PATH, "wb") as key_file:
            key_file.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        print(f"New private key generated and saved to {KEY_PATH}.")

    # Save public key in Base64 (X.509 DER format)
    x509_der_pub = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(PUBKEY_PATH, "w") as pub_file:
        pub_file.write(base64.b64encode(x509_der_pub).decode())

    return private_key


def sign_with_ed25519(private_key, data):
    """Sign data using an Ed25519 private key."""
    signature = private_key.sign(data.encode())
    return base64.b64encode(signature).decode()


def generate_command_token(command, expiry_seconds=300):
    """Generate a signed token for a command in JSON format."""
    private_key = load_or_generate_key()

    timestamp = int(time.time())
    expiry = timestamp + expiry_seconds
    nonce = secrets.token_hex(8)

    # Create the token data as a dictionary
    token_data = {
        "timestamp": timestamp,
        "nonce": nonce,
        "expiry": expiry,
        "command": command
    }
    message = "|".join(str(item) for item in token_data.values())
    print(repr(message))
    # Sign the message
    signature = sign_with_ed25519(private_key, message)

    # Add the signature to the token data
    token_data["signature"] = signature

    # Convert the entire token to a JSON string
    signed_token_json = json.dumps(token_data)
    encoded_json = base64.b64encode(signed_token_json.encode('utf-8')).decode('utf-8')


    return {
        "token": encoded_json,
        "expires_at": expiry,
        "command": command
    }


if __name__ == "__main__":
    # Ensure a command is provided
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <command_to_sign>")
        sys.exit(1)

    # Get command from CLI arguments
    command = " ".join(sys.argv[1:])  # Join all args as a single command

    # Generate signed token
    token_data = generate_command_token(command)

    # Output the signed token in JSON format
    print(token_data["token"])
