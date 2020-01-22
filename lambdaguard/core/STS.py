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
from lambdaguard.utils.arnparse import arnparse
from lambdaguard.utils.acl import ACL
from lambdaguard.utils.log import debug
from lambdaguard.core.AWS import AWS


class STS(AWS):
    def __init__(self, arn, profile=None, access_key_id=None, secret_access_key=None):
        super().__init__(arn, profile, access_key_id, secret_access_key)
        self.caller = self.get_caller_identity()
        self.arn = arnparse(self.caller['Arn'])
        self.acl = ACL(self.caller['Arn'])

    def get_caller_identity(self):
        '''
        Fetches STS Caller Identity
        '''
        try:
            return self.client.get_caller_identity()
        except Exception:
            exit(print(debug(self.arn.full)))
