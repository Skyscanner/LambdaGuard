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
import unittest
from copy import deepcopy
from pathlib import Path

from lambdaguard.security.LambdaWrite import LambdaWrite, is_write_action


class LambdaWriteHook(LambdaWrite):
    """
    Hooking AWS generators for data mocking
    """

    def __init__(self, args={}, policies=None):
        self.policies = policies
        super().__init__(args)

    def get_attached_local_policies(self):
        if not self.policies:
            return StopIteration
        for arn, version in self.policies.items():
            yield arn, version


class Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixtures = Path(__file__).parents[2].joinpath("fixtures")

        # Load policy version template
        cls.policy = json.loads(cls.fixtures.joinpath("PolicyVersion.json").read_text())
        # All lambda actions
        cls.policy_all_lambda = deepcopy(cls.policy)
        cls.policy_all_lambda["Document"]["Statement"][0]["Action"] = "lambda:*"
        # All actions
        cls.policy_all = deepcopy(cls.policy)
        cls.policy_all["Document"]["Statement"][0]["Action"] = ["*"]
        # All actions on all resources
        cls.policy_all_res = deepcopy(cls.policy)
        cls.policy_all_res["Document"]["Statement"][0]["Action"] = ["*"]
        cls.policy_all_res["Document"]["Statement"][0]["Resource"] = ["*"]
        # Deny effect
        cls.policy_deny = deepcopy(cls.policy)
        cls.policy_deny["Document"]["Statement"][0]["Effect"] = "Deny"
        # Unknown / unspecified effect
        cls.policy_no_effect = deepcopy(cls.policy)
        del cls.policy_no_effect["Document"]["Statement"][0]["Effect"]
        # Unknown / unspecified actions
        cls.policy_no_action = deepcopy(cls.policy)
        del cls.policy_no_action["Document"]["Statement"][0]["Action"]
        # Mock IAM policies for testing
        cls.policies = {
            "arn:aws:iam:policy1": cls.policy,
            "arn:aws:iam:policy2": cls.policy_deny,
            "arn:aws:iam:policy3": cls.policy_all_lambda,
            "arn:aws:iam:policy4": cls.policy_all,
            "arn:aws:iam:policy5": cls.policy_all_res,
        }

    def test_is_write_action(self):
        # True
        self.assertTrue(is_write_action("*"))
        self.assertTrue(is_write_action("LAMBDA:*"))
        self.assertTrue(is_write_action("lambda:Create*"))
        self.assertTrue(is_write_action("Lambda:TagResource"))
        # False
        self.assertFalse(is_write_action("iam:*"))
        self.assertFalse(is_write_action("lambda:GetLayerVersionByArn"))
        self.assertFalse(is_write_action("LAMBDA:ListFunctions"))
        self.assertFalse(is_write_action("lambda:get*"))

    def test_get_writes(self):
        # No WRITE permissions
        hook = LambdaWriteHook()
        self.assertEqual(hook.writes, {})
        # Custom WRITE permissions
        hook = LambdaWriteHook(policies=self.policies)
        for lambda_arn, policies in hook.writes.items():
            self.assertGreaterEqual(len(policies), 1)
            for policy in policies:
                self.assertIn(policy, self.policies)

    def test_get_attached_local_policies(self):
        hook = LambdaWriteHook()
        with self.assertRaises(StopIteration):
            next(hook.get_attached_local_policies())

    def test_parse(self):
        hook = LambdaWriteHook()
        # Empty policy
        with self.assertRaises(StopIteration):
            next(hook.parse({}))
        # Invalid policy
        with self.assertRaises(StopIteration):
            next(hook.parse({"policy": []}))
        with self.assertRaises(StopIteration):
            next(hook.parse({"Document": {"policy": []}}))
        # Policy not Allow-ed
        with self.assertRaises(StopIteration):
            next(hook.parse(self.policy_deny))
        # No Effect
        with self.assertRaises(StopIteration):
            next(hook.parse(self.policy_no_effect))
        # No Action
        with self.assertRaises(StopIteration):
            next(hook.parse(self.policy_no_action))
        # Identify all WRITE permissions
        arn, actions = next(hook.parse(self.policy))
        self.assertEqual(arn, "arn:aws:lambda:eu-west-1:0:function:functionName")
        expected_actions = [
            "lambda:TagResource",
            "lambda:UpdateFunctionConfiguration",
            "lambda:DeleteFunction",
            "lambda:PublishVersion",
        ]
        for e in expected_actions:
            self.assertIn(e, actions)
        # Identify wildcard permissions
        arn, actions = next(hook.parse(self.policy_all))
        self.assertEqual(actions, ["*"])
        arn, actions = next(hook.parse(self.policy_all_lambda))
        self.assertEqual(actions, ["lambda:*"])

    def test_get_for_lambda(self):
        # Denied policy
        hook = LambdaWriteHook(policies={"arn:aws:iam:policy_deny_write": self.policy_deny})
        writes = hook.get_for_lambda("arn:aws:lambda:eu-west-1:0:function:functionName")
        with self.assertRaises(StopIteration):
            next(writes)
        # All policies
        hook = LambdaWriteHook(policies=self.policies)
        writes = hook.get_for_lambda("arn:aws:lambda:eu-west-1:0:function:functionName")
        for _ in range(2):  # There should be 2 that apply
            actions = next(writes)
            print(actions)
        with self.assertRaises(StopIteration):
            next(writes)
