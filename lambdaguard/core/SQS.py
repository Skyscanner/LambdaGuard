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


class SQS(AWS):
    def __init__(self, arn, profile=None, access_key_id=None, secret_access_key=None):
        super().__init__(arn, profile, access_key_id, secret_access_key)

        self.url = ''

        self.get_queue_attributes()

        self.info = f'{self.url}'

    def get_queue_attributes(self):
        '''
        Fetches SQS Queue attributes
        '''
        try:
            self.url = f'https://{self.arn.region}.queue.amazonaws.com/{self.arn.account_id}/{self.arn.resource}'
            policy = self.client.get_queue_attributes(QueueUrl=self.url, AttributeNames=['Policy'])
            if 'Attributes' in policy:
                self.policy = json.loads(policy['Attributes']['Policy'])
        except Exception:
            debug(self.arn.full)
