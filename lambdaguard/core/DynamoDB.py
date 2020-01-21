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
from lambdaguard.utils.log import debug
from lambdaguard.core.AWS import AWS


class DynamoDB(AWS):
    def __init__(self, arn, profile=None, access_key_id=None, secret_access_key=None):
        super().__init__(arn, profile, access_key_id, secret_access_key)

        self.encryption = None

        self.describe_table()

    def describe_table(self):
        '''
        Fetches DynamoDB table metadata
        '''
        try:
            table = self.client.describe_table(TableName=self.arn.resource)['Table']
            if 'SSEDescription' in table:
                self.encryption = table['SSEDescription']
        except Exception:
            debug(self.arn.full)
