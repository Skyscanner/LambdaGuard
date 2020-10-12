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
from lambdaguard.core.AWS import AWS
from lambdaguard.utils.log import debug


class Role(AWS):
    def __init__(self, arn, profile=None, access_key_id=None, secret_access_key=None):
        super().__init__(arn, profile, access_key_id, secret_access_key)

        self.get_policy()

    def get_policy(self):
        """
        Fetches attached and inline policies
        """
        self.policy = {"roleName": self.arn.resource, "policies": []}

        # Collect attached policies
        try:
            policies = self.client.list_attached_role_policies(RoleName=self.arn.resource)
            for attached in policies["AttachedPolicies"]:
                info = self.client.get_policy(PolicyArn=attached["PolicyArn"])
                policy = self.client.get_policy_version(
                    PolicyArn=attached["PolicyArn"],
                    VersionId=info["Policy"]["DefaultVersionId"],
                )["PolicyVersion"]["Document"]
                self.policy["policies"].append(
                    {
                        "document": policy,
                        "name": attached["PolicyName"],
                        "arn": attached["PolicyArn"],
                        "type": "managed",
                    }
                )
        except Exception:
            debug(self.arn.full)

        # Collect inline policies
        try:
            policies = self.client.list_role_policies(RoleName=self.arn.resource)
            for name in policies["PolicyNames"]:
                policy = self.client.get_role_policy(RoleName=self.arn.resource, PolicyName=name)["PolicyDocument"]
                self.policy["policies"].append({"document": policy, "name": name, "type": "inline"})
        except Exception:
            debug(self.arn.full)
