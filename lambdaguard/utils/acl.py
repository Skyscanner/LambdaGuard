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
import json


class ACL(AWS):
    def __init__(self, arn, profile=None, access_key_id=None, secret_access_key=None):
        super().__init__(arn, profile, access_key_id, secret_access_key)
        self.permissions = {}
        self.get_permissions()

    def get_permissions(self):
        service_access_policies = self.client.list_policies_granting_service_access(
            Arn=self.arn.full,
            ServiceNamespaces=[
                "apigateway",
                "dynamodb",
                "kms",
                "lambda",
                "iam",
                "s3",
                "sns",
                "sqs",
                "sts"
            ]
        )["PoliciesGrantingServiceAccess"]
        history = {}
        for item in service_access_policies:
            namespace = item["ServiceNamespace"]
            self.permissions[namespace] = []

            for policy in item["Policies"]:
                if policy["PolicyType"] == "MANAGED":
                    policy_arn = policy["PolicyArn"]
                    if policy_arn not in history:
                        policy_version = self.client.get_policy(
                            PolicyArn=policy_arn
                        )["Policy"]["DefaultVersionId"]
                        policy_document = self.client.get_policy_version(
                            PolicyArn=policy_arn,
                            VersionId=policy_version
                        )["PolicyVersion"]["Document"]
                        history[policy_arn] = policy_document
                    self.permissions[namespace].append(history[policy_arn])

                elif policy["PolicyType"] == "INLINE":
                    policy_document = self.client.get_user_policy(
                        UserName=self.arn.resource,
                        PolicyName=policy["PolicyName"]
                    )["PolicyDocument"]
                    self.permissions[namespace].append(policy_document)

                else:
                    debug(policy["PolicyType"])

    def allowed(self, action):
        namespace = action.split(":")[0]
        if namespace not in self.permissions:
            return False  # Unknown service namespace
        policy_input = [json.dumps(_) for _ in self.permissions[namespace]]
        simulation_results = self.client.simulate_custom_policy(
            PolicyInputList=policy_input,
            ActionNames=[action]
        )["EvaluationResults"]
        for result in simulation_results:
            if result["EvalDecision"] == "allowed":
                return True  # Allowed
        return False  # Not allowed
