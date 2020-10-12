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
from pathlib import Path

from lambdaguard.security.PolicyStatement import PolicyStatement


class Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixtures = Path(__file__).parents[2].joinpath("fixtures")

    def test_is_unrestricted(self):
        policy = json.loads(self.fixtures.joinpath("PolicyUnrestricted.json").read_text())
        for statement in policy["Statement"]:
            print(statement)
            self.assertTrue(PolicyStatement(statement).is_unrestricted("Principal"))
            self.assertTrue(PolicyStatement(statement).is_unrestricted("Action"))

    def test_is_undefined(self):
        policy = json.loads(self.fixtures.joinpath("PolicyUnrestricted.json").read_text())
        for statement in policy["Statement"]:
            self.assertTrue(PolicyStatement(statement).is_undefined("Condition"))

    def test_audit(self):
        statement = {"Effect": "Allow", "Principal": "*", "Condition": {}}
        expected = "Service is publicly accessible"
        self.assertTrue(expected in next(PolicyStatement(statement).audit())["text"])

        statement = {"Effect": "Allow", "NotPrincipal": "arn:aws:"}
        expected = "NotPrincipal with Allow"
        self.assertTrue(expected in next(PolicyStatement(statement).audit())["text"])

        statement = {"Effect": "Allow", "Resource": "arn:aws:sqs:eu-west-1:*:queue"}
        expected = "Unrestricted AWS Account ID"
        self.assertTrue(expected in next(PolicyStatement(statement).audit())["text"])

        statement = {"Effect": "Allow", "Action": "sqs:*"}
        expected = "Unrestricted Action"
        self.assertTrue(expected in next(PolicyStatement(statement).audit())["text"])

        statement = {"Effect": "Allow", "NotAction": "sqs:SendMessage"}
        expected = "NotAction with Allow"
        self.assertTrue(expected in next(PolicyStatement(statement).audit())["text"])
