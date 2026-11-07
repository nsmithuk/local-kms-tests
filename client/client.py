import requests
import json
import time
from aws_requests_auth.aws_auth import AWSRequestsAuth


class KmsClient:
    """
    Simple KMS Client that allows the same request to easily be sent to either Local KMS, or AWS KMS.
    """

    def __init__(self,
                 kms_url,
                 aws_access_key=None,
                 aws_secret_access_key=None,
                 aws_session_token=None,
                 real_kms=False,
                 region='eu-west-2'):

        self.auth = None
        self.kms_url = kms_url
        self.real_kms = real_kms

        if real_kms is True:
            aws_kms_hostname = 'kms.%s.amazonaws.com' % region
            self.kms_url = 'https://%s/' % aws_kms_hostname
            self.auth = AWSRequestsAuth(aws_access_key=aws_access_key,
                                        aws_secret_access_key=aws_secret_access_key,
                                        aws_token=aws_session_token,
                                        aws_host=aws_kms_hostname,
                                        aws_region=region,
                                        aws_service='kms')

    def is_real_kms(self) -> bool:
        return self.real_kms

    def post(self, handler, payload=None):

        # If we're using real KMS we need to Throttle requests.
        if self.real_kms:
            time.sleep(1)

        if payload is None:
            # AWS always expects a payload, even if it's empty
            payload = {}

        response = requests.post(
            self.kms_url,
            auth=self.auth,
            headers={
                'X-Amz-Target': 'TrentService.%s' % handler,
                'Content-Type': 'application/x-amz-json-1.1'
            },
            json=payload,
        )

        try:
            content = json.loads(response.content)
        except ValueError:
            content = response.content

        if response.status_code != 200:
            print(content)

        return response.status_code, content
