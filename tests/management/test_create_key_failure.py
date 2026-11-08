import random
import string
import pytest

def random_string(length: int) -> str:
    alphabet = string.ascii_letters + string.digits
    return ''.join(random.choices(alphabet, k=length))

def test_create_description_failure(kms_client):
    code, content = kms_client.post('CreateKey',{
        'Description': random_string(8192 + 1)
    })

    assert code == 400
    assert isinstance(content, dict)
    assert content.get('__type') == 'ValidationException'
    assert content.get('message').startswith('1 validation error detected: ')

def test_create_policy_failure(kms_client):
    code, content = kms_client.post('CreateKey',{
        'Policy': random_string(32768 + 1)
    })

    assert code == 400
    assert isinstance(content, dict)
    assert content.get('__type') == 'MalformedPolicyDocumentException'

    # TODO - try an invalid policy

def test_create_duplicate_keyspec_failure(kms_client):
    code, content = kms_client.post('CreateKey',{
        'KeySpec': "ECC_NIST_P256",
        'CustomerMasterKeySpec': "ECC_NIST_P256"
    })

    assert code == 400
    assert isinstance(content, dict)
    assert content.get('__type') == 'ValidationException'
    assert content.get('message').startswith('You cannot specify KeySpec and CustomerMasterKeySpec in the same request.')
