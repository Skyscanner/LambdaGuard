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
from lambdaguard.core.APIGateway import APIGateway
from lambdaguard.security.Public import Public


class Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixtures = Path(__file__).parents[1].joinpath('fixtures')

    def test_public_ok(self):
        expected = StopIteration
        obj = APIGateway('arn:aws:execute-api:eu-west-1:0:id/stage/method/path')
        obj.policy = {'test': 'test'}
        with self.assertRaises(expected):
            next(Public(obj).audit())

    def test_public(self):
        arn = 'arn:aws:execute-api:eu-west-1:0:id/stage/method/path'
        expected = {
            'level': 'high',
            'text': 'Service is publicly accessible due to missing Resource-based policy'
        }
        self.assertEqual(expected, next(Public(APIGateway(arn)).audit()))