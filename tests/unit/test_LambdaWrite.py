"""
Copyright 2019 Skyscanner Ltd

Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.
"""
import unittest
import json
from pathlib import Path
from copy import deepcopy
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
            return 'arn', {'policy': {}}
        for arn, version in self.policies.items():
            yield arn, version


class Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixtures = Path(__file__).parents[1].joinpath('fixtures')

        # Load policy version template
        policy = json.loads(
            cls.fixtures.joinpath('PolicyVersion.json').read_text()
        )
        # All lambda actions
        policy_all_lambda = deepcopy(policy)
        policy_all_lambda['Document']['Statement'][0]['Action'] = 'lambda:*'
        # All actions
        policy_all = deepcopy(policy)
        policy_all['Document']['Statement'][0]['Action'] = ['*']

        # Mock IAM policies for testing
        cls.policies = {
            'arn:aws:iam:policy1': policy,
            'arn:aws:iam:policy2': policy_all_lambda,
            'arn:aws:iam:policy3': policy_all
        }

    def test_is_write_action(self):
        # True
        self.assertTrue(is_write_action('*'))
        self.assertTrue(is_write_action('LAMBDA:*'))
        self.assertTrue(is_write_action('lambda:Create*'))
        self.assertTrue(is_write_action('Lambda:TagResource'))
        # False
        self.assertFalse(is_write_action('iam:*'))
        self.assertFalse(is_write_action('lambda:GetLayerVersionByArn'))
        self.assertFalse(is_write_action('LAMBDA:ListFunctions'))
        self.assertFalse(is_write_action('lambda:get*'))

    def test_get_writes(self):
        # No WRITE
        hook = LambdaWriteHook()
        self.assertEqual(hook.writes, {})
        # Custom WRITE
        hook = LambdaWriteHook(policies=self.policies)
        for lambda_arn, policies in hook.writes.items():
            self.assertEqual(len(policies), len(self.policies))
            for policy in policies:
                self.assertIn(policy, self.policies)

    def test_get_for_lambda(self):
        hook = LambdaWriteHook(policies=self.policies)
