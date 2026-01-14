from base64 import b64decode
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
import pytest
from . import ASYMMETRIC_KEY_ALIASES
from cryptography.hazmat.primitives.serialization import (
    load_der_public_key,
    load_der_private_key,
)

@pytest.mark.parametrize("key_alias", ASYMMETRIC_KEY_ALIASES)
def test_create_key_valid_combinations(kms_client, key_alias):
    code, content = kms_client.post('GetPublicKey',{
        'KeyId': key_alias
    })

    assert code == 200
    assert isinstance(content, dict)
    assert 'PublicKey' in content
    assert 'KeySpec' in content
    assert len(content['PublicKey']) > 0

    pub = load_der_public_key(b64decode(content['PublicKey']))

    assert isinstance(pub, ec.EllipticCurvePublicKey), f"PublicKey type mismatch: {type(pub)!r}"
