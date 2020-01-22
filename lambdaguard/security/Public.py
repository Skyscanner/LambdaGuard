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


class Public:
    def __init__(self, item):
        self.item = item

    def audit(self):
        if self.item.arn.service == 'apigateway':
            if self.item.policy:
                return

            apiKeyRequired = False
            authorizationType = None
            for res in self.item.resources:
                if res['apiKeyRequired']:
                    apiKeyRequired = True
                if res['authorizationType'] != 'NONE':
                    authorizationType = res['authorizationType']

            if not apiKeyRequired and not authorizationType:
                yield {
                    'level': 'high',
                    'text': 'Service is publicly accessible due to missing Resource-based policy'
                }
