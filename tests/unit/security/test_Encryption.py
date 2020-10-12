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

from lambdaguard.core.DynamoDB import DynamoDB
from lambdaguard.core.S3 import S3
from lambdaguard.security.Encryption import Encryption


class Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixtures = Path(__file__).parents[2].joinpath("fixtures")

    def test_encryption_ok(self):
        expected = StopIteration

        obj = S3("arn:aws:s3::0:bucket")
        obj.encryption = {"test": "test"}
        with self.assertRaises(expected):
            next(Encryption(obj).audit())

        obj = DynamoDB("arn:aws:dynamodb:eu-west-1:0:table/name")
        obj.encryption = {"test": "test"}
        with self.assertRaises(expected):
            next(Encryption(obj).audit())

    def test_encryption_missing(self):
        expected = {"level": "medium", "text": "Objects are stored without encryption"}

        arn = "arn:aws:s3::0:bucket"
        self.assertEqual(expected, next(Encryption(S3(arn)).audit()))

        arn = "arn:aws:dynamodb:eu-west-1:0:table/name"
        self.assertEqual(expected, next(Encryption(DynamoDB(arn)).audit()))
