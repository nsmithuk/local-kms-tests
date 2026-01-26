from base64 import b64decode

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_der_public_key

from tests.constants import SEED_ALIAS_RSA_2048_SIGN_VERIFY


def test_get_public_key_rsa_shape(kms_client) -> None:
    code, content = kms_client.post(
        "GetPublicKey",
        {
            "KeyId": SEED_ALIAS_RSA_2048_SIGN_VERIFY,
        },
    )

    assert code == 200
    assert isinstance(content, dict)
    assert "PublicKey" in content
    assert "KeySpec" in content

    public_key = load_der_public_key(b64decode(content["PublicKey"]))
    assert isinstance(public_key, rsa.RSAPublicKey)
