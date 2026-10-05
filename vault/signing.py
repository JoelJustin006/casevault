"""Ed25519 digital signatures for officers and ledger blocks."""
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


def generate_keypair():
    """Return (private_pem, public_pem) as strings."""
    private = ed25519.Ed25519PrivateKey.generate()
    public  = private.public_key()

    priv_pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    pub_pem = public.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    return priv_pem, pub_pem


def sign_payload(private_pem, payload_str):
    """Sign a payload string with an Ed25519 private key. Returns hex signature."""
    private = serialization.load_pem_private_key(private_pem.encode(), password=None)
    signature = private.sign(payload_str.encode())
    return signature.hex()


def verify_signature(public_pem, payload_str, signature_hex):
    """True if the hex signature is valid for the payload under the public key."""
    try:
        public = serialization.load_pem_public_key(public_pem.encode())
        public.verify(bytes.fromhex(signature_hex), payload_str.encode())
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False