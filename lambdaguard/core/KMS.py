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


class KMS(AWS):
    def __init__(self, arn, profile=None, access_key_id=None, secret_access_key=None):
        super().__init__(arn, profile, access_key_id, secret_access_key)

        self.policies = {}
        self.rotation = False
        self.info = 'https://{0}.console.aws.amazon.com/kms/home?region={0}#/kms/keys/{1}/'.format(
            self.arn.region,
            self.arn.resource
        )

        self.get_policies()

    def get_policies(self):
        '''
        Fetches list of applicable key policy names
        '''
        try:
            paginator = self.client.get_paginator('list_key_policies')
            pages = paginator.paginate(KeyId=self.arn.resource)
            for page in pages:
                for policy_name in page['PolicyNames']:
                    self.get_policy(policy_name)
        except Exception:
            debug(self.arn.full)

    def get_policy(self, policy_name):
        '''
        Fetches key policy by name
        '''
        try:
            policy = json.loads(self.client.get_key_policy(
                KeyId=self.arn.resource,
                PolicyName=policy_name
            )['Policy'])
            self.policies[policy_name] = policy
        except Exception:
            debug(self.arn.full)

    def get_rotation_status(self):
        '''
        Fetches automatic key rotation status
        '''
        try:
            status = self.client.get_key_rotation_status(KeyId=self.arn.resource)
            self.rotation = status['KeyRotationEnabled']
        except Exception:
            debug(self.arn.full)
