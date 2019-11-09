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
from lambdaguard.security.LambdaWrite import LambdaWrite


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
        for arn, version in self.policies:
            yield arn, version


class Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixtures = Path(__file__).parents[1].joinpath('fixtures')

    def test_get_for_lambda(self):
        hook = LambdaWriteHook()
        self.assertEqual(hook.writes, {})

