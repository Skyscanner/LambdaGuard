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
import unittest
from pathlib import Path

from lambdaguard.core.APIGateway import APIGateway
from lambdaguard.security.Public import Public


class Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixtures = Path(__file__).parents[2].joinpath("fixtures")

    def test_public_ok(self):
        expected = StopIteration
        obj = APIGateway("arn:aws:execute-api:eu-west-1:0:id/stage/method/path")
        obj.policy = {"test": "test"}
        with self.assertRaises(expected):
            next(Public(obj).audit())

    def test_public(self):
        obj = APIGateway("arn:aws:execute-api:eu-west-1:0:id/stage/method/path")

        # No policy and API Key not required
        expected = {
            "level": "high",
            "text": "Service is publicly accessible due to missing Resource-based policy",
        }
        obj.policy = {}
        obj.resources = [
            {
                "id": "0",
                "method": "GET",
                "path": "/",
                "apiKeyRequired": False,
                "authorizationType": "NONE",
            }
        ]
        self.assertEqual(expected, next(Public(obj).audit()))

        # No policy and API Key required
        expected = StopIteration
        obj.resources = [
            {
                "id": "0",
                "method": "GET",
                "path": "/",
                "apiKeyRequired": True,
                "authorizationType": "NONE",
            }
        ]
        with self.assertRaises(expected):
            next(Public(obj).audit())

        # No policy and Authorization Type set
        expected = StopIteration
        obj.resources = [
            {
                "id": "0",
                "method": "GET",
                "path": "/",
                "apiKeyRequired": False,
                "authorizationType": "AWS_IAM",
            }
        ]
        with self.assertRaises(expected):
            next(Public(obj).audit())
