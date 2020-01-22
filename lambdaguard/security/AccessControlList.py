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


class AccessControlList:
    def __init__(self, acl):
        self.acl = acl

    def audit(self):
        uris = {
            'http://acs.amazonaws.com/groups/global/AllUsers': 'Everyone',
            'http://acs.amazonaws.com/groups/global/AuthenticatedUsers': 'Authenticated AWS users'
        }

        if not self.acl:
            yield {
                'level': 'info',
                'text': 'Bucket ACL is not defined'
            }
        else:
            for acl in self.acl['Grants']:
                if acl['Grantee']['Type'] == 'Group':
                    if acl['Grantee']['URI'] in uris:
                        yield {
                            'level': 'high',
                            'text': f'Public Bucket ACL: {acl["Permission"]} access for {uris[acl["Grantee"]["URI"]]}'
                        }
