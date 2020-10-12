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
from lambdaguard.security.PrivilegeEscalation import PrivilegeEscalation
from lambdaguard.utils.arnparse import arnparse


class PolicyStatement:
    def __init__(self, statement, policy=None):
        self.statement = statement
        self.policy = policy
        self.vulnerabilities = []
        self.recommendations = []

    def audit(self):
        if type(self.statement) != dict:
            return None
        if self.statement["Effect"] != "Allow":
            return None

        # Where
        where = "in Policy Statement"
        if self.policy:
            where = f'in Role Policy {self.policy["name"]}'
        elif "Sid" in self.statement:
            where = f'{where} Sid {self.statement["Sid"]}'

        # Principal
        if self.is_unrestricted("Principal"):
            if self.is_undefined("Condition"):
                yield {
                    "level": "high",
                    "text": (
                        "Service is publicly accessible due to unrestricted "
                        f"Principal and undefined Condition {where}\n"
                        "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html"
                    ),
                }

        # NotPrincipal
        if self.get("NotPrincipal"):
            yield {
                "level": "high",
                "text": (
                    "Anonymous or unauthenticated users may have access to this "
                    f"service due to using NotPrincipal with Allow {where}\n"
                    "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notprincipal.html"
                ),
            }
            yield {"level": "info", "text": f"Use NotPrincipal with Deny {where}"}

        # Resource
        if self.is_unrestricted("Resource"):
            if self.is_unrestricted("Action"):
                if self.is_undefined("Condition"):
                    yield {
                        "level": "info",
                        "text": (
                            "Service can perform any operation on any service due "
                            f"to unrestricted Resource, unrestricted Action and undefined Condition {where}"
                        ),
                    }
            elif self.is_undefined("Condition"):
                operations = list(set([x.split(":")[0] for x in self.get("Action")]))
                for _ in operations:
                    if _ not in [
                        "sqs",
                        "s3",
                        "iam",
                        "sns",
                        "vpc",
                        "ec2",
                        "ecs",
                        "es",
                        "logs",
                        "dynamodb",
                        "kms",
                        "cloudformation",
                    ]:
                        operations.pop(operations.index(_))
                if len(operations):
                    yield {
                        "level": "info",
                        "text": (
                            f'Service can perform {", ".join(operations)} operations on '
                            f"any service due to unrestricted Resource and undefined Condition {where}"
                        ),
                    }
        else:
            for resource in self.get("Resource"):
                arn = arnparse(resource)
                if arn.account_id == "*":
                    yield {
                        "level": "low",
                        "text": f"Unrestricted AWS Account ID in {arn.service} {resource} {where}",
                    }

        # Action
        for action in self.get("Action"):
            if action == "*" or action.split(":")[1] == "*":
                yield {
                    "level": "low",
                    "text": (
                        f"Unrestricted Action {action} {where}\n"
                        "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege"
                    ),
                }

        # NotAction
        if self.get("NotAction"):
            yield {
                "level": "medium",
                "text": (
                    f"Users may have more permissions than intended due to using NotAction with Allow {where}\n"
                    "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notaction.html"
                ),
            }
            yield {"level": "info", "text": f"Use NotAction with Deny {where}"}

        # Condition
        if self.is_undefined("Condition"):
            yield {
                "level": "info",
                "text": f"Use policy Conditions for extra security {where}",
            }

        # Managed vs Inline policies
        if self.policy and self.policy["type"] == "inline":
            yield {
                "level": "info",
                "text": f"Use Customer Managed policies instead of Inline policies {where}",
            }

        # Privilege Escalation via IAM permissions
        yield from PrivilegeEscalation(self.get("Action")).audit()

    def get(self, idx):
        """
        Returns a list of items from given index in statement
        """
        if idx not in self.statement:
            return []

        if type(self.statement[idx]) == str:
            ret = [self.statement[idx]]
        else:
            ret = self.statement[idx]
        return ret

    def is_unrestricted(self, idx):
        """
        Check if index is unrestricted in statement
        Example: unrestricted('Resource')
        """
        matches = [
            "*",
            ["*"],
            {"AWS": "*"},
            {"AWS": ["*"]},
            [{"AWS": "*"}],
            [{"AWS": ["*"]}],
        ]

        if self.statement["Effect"] == "Deny":
            return False

        if idx in self.statement:
            if self.statement[idx] in matches:
                return True
            elif type(self.statement[idx]) == str:  # like sqs:*
                _ = self.statement[idx].split(":", 1)
                if len(_) > 1 and _[1] in matches:
                    return True
            elif type(self.statement[idx]) == list:  # like sqs:*
                for _ in self.statement[idx]:
                    _ = _.split(":", 1)
                    if len(_) > 1 and _[1] in matches:
                        return True
            elif type(self.statement[idx]) == dict:  # like {'AWS': ...}
                if "AWS" in self.statement[idx]:
                    if type(self.statement[idx]["AWS"]) == list:
                        for _ in self.statement[idx]["AWS"]:
                            if _ in matches:
                                return True

        return False

    def is_undefined(self, idx):
        """
        Check if index is unrestricted in statement
        Example: undefined(statement, 'Condition')
        """
        if self.statement["Effect"] == "Deny":
            return False

        if idx not in self.statement or self.statement[idx] == {}:
            return True

        return False
