import hashlib

import pytest
from base64 import b64encode, b64decode
import mldsa_mu
import random
from tests.constants import SEED_ALIAS_SYMMETRIC_ENCRYPT_DECRYPT

DATA_KEY_CASES = [
    pytest.param("AES_128", id="aes_128"),
    pytest.param("AES_256", id="aes_256"),
]

@pytest.mark.parametrize("data_key_spec", DATA_KEY_CASES)
def test_generate_data_key_spec(
    kms_client,
    data_key_spec: str,
) -> None:

    key_id = SEED_ALIAS_SYMMETRIC_ENCRYPT_DECRYPT

    code, content = kms_client.post('GenerateDataKey',{
        'KeyId': key_id,
        'KeySpec': data_key_spec,
    })

    assert code == 200
    assert isinstance(content, dict)
    assert len(content.get('Plaintext', '')) > 0
    assert len(content.get('CiphertextBlob', '')) > 0

    plaintext = content.get('Plaintext')

    #---

    code, content = kms_client.post('Decrypt',{
        'EncryptionAlgorithm': "SYMMETRIC_DEFAULT",
        'CiphertextBlob': content.get('CiphertextBlob'),
    })

    assert code == 200
    assert isinstance(content, dict)
    assert len(content.get('Plaintext', '')) > 0

    assert content.get('Plaintext') == plaintext

    #--------------------------------------------
    # GenerateDataKeyWithoutPlaintext

    code, content = kms_client.post('GenerateDataKeyWithoutPlaintext',{
        'KeyId': key_id,
        'KeySpec': data_key_spec,
    })

    assert code == 200
    assert isinstance(content, dict)
    assert len(content.get('Plaintext', '')) == 0 # We should not get this now.
    assert len(content.get('CiphertextBlob', '')) > 0

    #---

    code, content = kms_client.post('Decrypt',{
        'EncryptionAlgorithm': "SYMMETRIC_DEFAULT",
        'CiphertextBlob': content.get('CiphertextBlob'),
    })

    assert code == 200
    assert isinstance(content, dict)
    assert len(content.get('Plaintext', '')) > 0


def test_generate_data_key_bytes(
    kms_client,
) -> None:

    key_id = SEED_ALIAS_SYMMETRIC_ENCRYPT_DECRYPT

    code, content = kms_client.post('GenerateDataKey',{
        'KeyId': key_id,
        'NumberOfBytes': 1024,
    })

    assert code == 200
    assert isinstance(content, dict)
    assert len(content.get('Plaintext', '')) > 0
    assert len(content.get('CiphertextBlob', '')) > 0

    plaintext = content.get('Plaintext')

    #---

    code, content = kms_client.post('Decrypt',{
        'EncryptionAlgorithm': "SYMMETRIC_DEFAULT",
        'CiphertextBlob': content.get('CiphertextBlob'),
    })

    assert code == 200
    assert isinstance(content, dict)
    assert len(content.get('Plaintext', '')) > 0

    assert content.get('Plaintext') == plaintext

    #--------------------------------------------
    # GenerateDataKeyWithoutPlaintext

    code, content = kms_client.post('GenerateDataKeyWithoutPlaintext',{
        'KeyId': key_id,
        'NumberOfBytes': 1024,
    })

    assert code == 200
    assert isinstance(content, dict)
    assert len(content.get('Plaintext', '')) == 0 # We should not get this now.
    assert len(content.get('CiphertextBlob', '')) > 0

    #---

    code, content = kms_client.post('Decrypt',{
        'EncryptionAlgorithm': "SYMMETRIC_DEFAULT",
        'CiphertextBlob': content.get('CiphertextBlob'),
    })

    assert code == 200
    assert isinstance(content, dict)
    assert len(content.get('Plaintext', '')) > 0
