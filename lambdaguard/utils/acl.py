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

from lambdaguard.core.AWS import AWS
from lambdaguard.utils.arnparse import arnparse
from lambdaguard.utils.log import debug


class ACL(AWS):
    def __init__(self, arn, profile=None, access_key_id=None, secret_access_key=None):
        # Make sure we use IAM client
        super().__init__("arn:aws:iam::", profile, access_key_id, secret_access_key)
        self.arn = arnparse(arn)
        self.policy_documents = []
        self.permissions = []

        if self.arn.resource_type == "user":
            self.get_user_permissions()
        elif self.arn.resource_type == "assumed-role":
            self.get_role_permissions()

    def get_user_permissions(self):
        try:
            policies = self.client.list_policies_granting_service_access(
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
                    "sts",
                ],
            )["PoliciesGrantingServiceAccess"]
            for item in policies:
                for policy in item["Policies"]:
                    self.policy_documents.append(self.get_policy_documents(policy))
        except Exception:
            debug(self.arn.full)

    def get_role_permissions(self):
        try:
            policies = self.client.list_attached_role_policies(RoleName=self.arn.resource)["AttachedPolicies"]
            for policy in policies:
                self.policy_documents.append(self.get_policy_documents(policy))
        except Exception:
            debug(self.arn.full)

    def get_policy_documents(self, policy):
        history = {}

        if "PolicyType" not in policy or policy["PolicyType"] == "MANAGED":
            policy_arn = policy["PolicyArn"]
            if policy_arn not in history:
                policy_version = self.client.get_policy(PolicyArn=policy_arn)["Policy"]["DefaultVersionId"]
                policy_document = self.client.get_policy_version(PolicyArn=policy_arn, VersionId=policy_version)[
                    "PolicyVersion"
                ]["Document"]
                history[policy_arn] = policy_document
            return history[policy_arn]

        elif policy["PolicyType"] == "INLINE":
            policy_document = self.client.get_user_policy(UserName=self.arn.resource, PolicyName=policy["PolicyName"])[
                "PolicyDocument"
            ]
            return policy_document

    def allowed(self, action):
        if action in self.permissions:
            return True  # Previously checked
        policy_input = [json.dumps(_) for _ in self.policy_documents]
        simulation_results = self.client.simulate_custom_policy(PolicyInputList=policy_input, ActionNames=[action])[
            "EvaluationResults"
        ]
        for result in simulation_results:
            if result["EvalDecision"] == "allowed":
                self.permissions.append(action)
                return True  # Allowed
        return False  # Not allowed
