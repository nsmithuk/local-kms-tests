import os

import pytest

from client import KmsClient


@pytest.fixture(scope="session")
def kms_client():
    yield KmsClient(
        aws_access_key=os.getenv('AWS_ACCESS_KEY_ID', 'Test'),
        aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY', 'Test'),
        aws_session_token=os.getenv('AWS_SESSION_TOKEN', 'Test'),
        kms_url=os.getenv('KMS_URL', 'http://localhost:8080'),
        real_kms=os.getenv('REAL_KMS', '').lower() in ('1', 'true', 'yes'),
    )


@pytest.fixture(scope="session")
def symmetric_key(kms_client):
    """
    Create a temporary symmetric key for use in tests that require one.
    The key is marked for deletion once the tests have finished.
    We don't actually test the creation/deletion process here; it's assumed to work.
    :param kms_client:
    :return:
    """
    code, content = kms_client.post('CreateKey')

    yield content['KeyMetadata']

    code, unused = kms_client.post(
        'ScheduleKeyDeletion',
        {'KeyId': content['KeyMetadata']['KeyId'], 'PendingWindowInDays': 7},
    )
    if code != 200:
        raise ValueError(
            'Unable to delete test key %s' % content['KeyMetadata']['KeyId']
        )


@pytest.fixture(scope="session")
def rsa_signing_key(kms_client):
    """
    Create a temporary RSA Signing key for use in tests that require one.
    The key is marked for deletion once the tests have finished.
    We don't actually test the creation/deletion process here; it's assumed to work.
    :param kms_client:
    :return:
    """
    code, content = kms_client.post(
        'CreateKey',
        {
            "KeySpec": 'RSA_2048',
            "KeyUsage": 'SIGN_VERIFY',
        },
    )

    yield content['KeyMetadata']

    code, unused = kms_client.post(
        'ScheduleKeyDeletion',
        {'KeyId': content['KeyMetadata']['KeyId'], 'PendingWindowInDays': 7},
    )
    if code != 200:
        raise ValueError(
            'Unable to delete test key %s' % content['KeyMetadata']['KeyId']
        )


@pytest.fixture(scope="session")
def rsa_encryption_key(kms_client):
    """
    Create a temporary RSA Encryption for use in tests that require one.
    The key is marked for deletion once the tests have finished.
    We don't actually test the creation/deletion process here; it's assumed to work.
    :param kms_client:
    :return:
    """
    code, content = kms_client.post(
        'CreateKey',
        {
            "KeySpec": 'RSA_2048',
            "KeyUsage": 'ENCRYPT_DECRYPT',
        },
    )

    yield content['KeyMetadata']

    code, unused = kms_client.post(
        'ScheduleKeyDeletion',
        {'KeyId': content['KeyMetadata']['KeyId'], 'PendingWindowInDays': 7},
    )
    if code != 200:
        raise ValueError(
            'Unable to delete test key %s' % content['KeyMetadata']['KeyId']
        )


@pytest.fixture(scope="session")
def ecc_signing_key(kms_client):
    """
    Create a temporary ECC Signing for use in tests that require one.
    The key is marked for deletion once the tests have finished.
    We don't actually test the creation/deletion process here; it's assumed to work.
    :param kms_client:
    :return:
    """
    code, content = kms_client.post(
        'CreateKey',
        {
            "KeySpec": 'ECC_NIST_P256',
            "KeyUsage": 'SIGN_VERIFY',
        },
    )

    yield content['KeyMetadata']

    code, unused = kms_client.post(
        'ScheduleKeyDeletion',
        {'KeyId': content['KeyMetadata']['KeyId'], 'PendingWindowInDays': 7},
    )
    if code != 200:
        raise ValueError(
            'Unable to delete test key %s' % content['KeyMetadata']['KeyId']
        )
