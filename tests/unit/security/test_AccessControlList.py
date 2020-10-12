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

from lambdaguard.security.AccessControlList import AccessControlList


class Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixtures = Path(__file__).parents[2].joinpath("fixtures")

    def test_ok(self):
        acl = json.loads(self.fixtures.joinpath("AccessControlListOk.json").read_text())
        expected = StopIteration
        with self.assertRaises(expected):
            next(AccessControlList(acl).audit())

    def test_not_defined(self):
        acl = None
        expected = {"level": "info", "text": "Bucket ACL is not defined"}
        self.assertEqual(expected, next(AccessControlList(acl).audit()))

    def test_public(self):
        acl = json.loads(self.fixtures.joinpath("AccessControlListPublic.json").read_text())
        result = AccessControlList(acl).audit()

        expected = {
            "level": "high",
            "text": "Public Bucket ACL: READ access for Everyone",
        }
        self.assertEqual(expected, next(result))

        expected = {
            "level": "high",
            "text": "Public Bucket ACL: WRITE access for Everyone",
        }
        self.assertEqual(expected, next(result))

        expected = {
            "level": "high",
            "text": "Public Bucket ACL: FULL_CONTROL access for Authenticated AWS users",
        }
        self.assertEqual(expected, next(result))


if __name__ == "__main__":
    unittest.main()
