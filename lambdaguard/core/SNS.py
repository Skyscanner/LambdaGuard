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


class SNS(AWS):
    def __init__(self, arn, profile=None, access_key_id=None, secret_access_key=None):
        super().__init__(arn, profile, access_key_id, secret_access_key)

        self.get_topic_attributes()

    def get_topic_attributes(self):
        '''
        Fetches SNS Topic attributes
        '''
        try:
            self.policy = json.loads(
                self.client.get_topic_attributes(TopicArn=self.arn.full)['Attributes']['Policy']
            )
        except Exception:
            debug(self.arn.full)
