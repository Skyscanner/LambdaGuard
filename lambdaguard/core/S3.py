"""
Copyright 2020 Skyscanner Ltd

Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.
"""
import json
from lambdaguard.utils.log import debug
from lambdaguard.core.AWS import AWS


class S3(AWS):
    def __init__(self, arn, profile=None, access_key_id=None, secret_access_key=None):
        super().__init__(arn, profile, access_key_id, secret_access_key)

        self.acl = None
        self.encryption = None

        self.get_bucket_policy()
        self.get_bucket_acl()
        self.get_bucket_encryption()

        self.info = (
            f'http://{self.arn.resource}.s3.amazonaws.com\n\n' +
            f'https://console.aws.amazon.com/s3/buckets/{self.arn.resource}/?tab=permissions'
        )

    def get_bucket_policy(self):
        '''
        Fetches S3 Bucket (Resource-based) policy
        '''
        try:
            policy = self.client.get_bucket_policy(Bucket=self.arn.resource)
            self.policy = json.loads(policy['Policy'])
        except Exception:
            debug(self.arn.full)

    def get_bucket_acl(self):
        '''
        Fetches S3 Bucket (Resource-based) Access Control List
        '''
        try:
            self.acl = self.client.get_bucket_acl(Bucket=self.arn.resource)
        except Exception:
            debug(self.arn.full)

    def get_bucket_encryption(self):
        '''
        Fetches S3 Bucket encryption settings
        '''
        try:
            self.encryption = self.client.get_bucket_encryption(Bucket=self.arn.resource)
        except Exception:
            debug(self.arn.full)
