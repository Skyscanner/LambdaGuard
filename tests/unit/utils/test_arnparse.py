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

from lambdaguard.utils.arnparse import arnparse


class Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixtures = Path(__file__).parents[2].joinpath("fixtures")

    def test_arnparse_to_dict(self):
        arn_str = "arn:aws:lambda:eu-west-1:0:function:function-name"
        arn = arnparse(arn_str)
        self.assertEqual(
            arn.to_dict(),
            {
                "full": arn_str,
                "partition": "aws",
                "service": "lambda",
                "region": "eu-west-1",
                "account_id": "0",
                "resource_type": "function",
                "resource": "function-name",
            },
        )

    def test_arnparse_invalid(self):
        with self.assertRaises(ValueError):
            arnparse("")
        with self.assertRaises(ValueError):
            arnparse("arn:aws:service")

    def test_arnparse_lambda(self):
        arn_str = "arn:aws:lambda:eu-west-1:0:function:function-name"
        arn = arnparse(arn_str)
        self.assertEqual(arn.full, arn_str)
        self.assertEqual(arn.partition, "aws")
        self.assertEqual(arn.service, "lambda")
        self.assertEqual(arn.region, "eu-west-1")
        self.assertEqual(arn.account_id, "0")
        self.assertEqual(arn.resource_type, "function")
        self.assertEqual(arn.resource, "function-name")

    def test_arnparse_iam(self):
        arn_str = "arn:aws:iam::0:role/service-role/role-name"
        arn = arnparse(arn_str)
        self.assertEqual(arn.full, arn_str)
        self.assertEqual(arn.partition, "aws")
        self.assertEqual(arn.service, "iam")
        self.assertEqual(arn.region, None)
        self.assertEqual(arn.account_id, "0")
        self.assertEqual(arn.resource_type, "role/service-role")
        self.assertEqual(arn.resource, "role-name")

        arn_str = "arn:aws:iam::0:policy/service-role/role-name"
        arn = arnparse(arn_str)
        self.assertEqual(arn.resource_type, "policy/service-role")
        self.assertEqual(arn.resource, "role-name")

        arn_str = "arn:aws:iam::0:user/user-name"
        arn = arnparse(arn_str)
        self.assertEqual(arn.resource_type, "user")
        self.assertEqual(arn.resource, "user-name")

    def test_arnparse_s3(self):
        arn_str = "arn:aws:s3:::bucket-name"
        arn = arnparse(arn_str)
        self.assertEqual(arn.resource_type, None)
        self.assertEqual(arn.resource, "bucket-name")

    def test_arnparse_kms(self):
        arn_str = "arn:aws:kms:eu-west-1:0:key/key-id"
        arn = arnparse(arn_str)
        self.assertEqual(arn.resource_type, "key")
        self.assertEqual(arn.resource, "key-id")

    def test_arnparse_sqs(self):
        arn_str = "arn:aws:sqs:eu-west-1:0:queue-name"
        arn = arnparse(arn_str)
        self.assertEqual(arn.resource_type, None)
        self.assertEqual(arn.resource, "queue-name")

    def test_arnparse_sns(self):
        arn_str = "arn:aws:sns:us-east-1:0:topic-name"
        arn = arnparse(arn_str)
        self.assertEqual(arn.resource_type, None)
        self.assertEqual(arn.resource, "topic-name")

    def test_arnparse_dynamodb(self):
        arn_str = "arn:aws:dynamodb:us-west-2:0:table/table-name"
        arn = arnparse(arn_str)
        self.assertEqual(arn.resource_type, "table")
        self.assertEqual(arn.resource, "table-name")

    def test_arnparse_logs(self):
        arn_str = "arn:aws:logs:eu-west-1:0:log-group:/aws/lambda/function:*"
        arn = arnparse(arn_str)
        self.assertEqual(arn.resource_type, "log-group")
        self.assertEqual(arn.resource, "/aws/lambda/function:*")

    def test_arnparse_apigateway(self):
        arn_str = "arn:aws:execute-api:us-east-1:0:api-id/stage/verb/path"
        arn = arnparse(arn_str)
        self.assertEqual(arn.service, "apigateway")
        self.assertEqual(arn.resource_type, "api-id")
        self.assertEqual(arn.resource, "stage/verb/path")

        arn_str = "arn:aws:execute-api:*:*:*"
        arn = arnparse(arn_str)
        self.assertEqual(arn.resource_type, "*")
        self.assertEqual(arn.resource, "")

        arn_str = "arn:aws:execute-api:us-east-1:*:api-id/stage/*"
        arn = arnparse(arn_str)
        self.assertEqual(arn.resource_type, "api-id")
        self.assertEqual(arn.resource, "stage/*")
