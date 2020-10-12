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

from lambdaguard.utils.iterator import iterate


class Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixtures = Path(__file__).parents[2].joinpath("fixtures")

    def test_iterate(self):
        # Empty
        with self.assertRaises(StopIteration):
            next(iterate(""))
        # Invalid
        with self.assertRaises(TypeError):
            next(iterate({"a": "b"}))
        with self.assertRaises(TypeError):
            next(iterate(None))
        # String
        i = iterate("string")
        self.assertEqual(next(i), "string")
        with self.assertRaises(StopIteration):
            next(i)
        # List
        i = iterate(["list"])
        self.assertEqual(next(i), "list")
        with self.assertRaises(StopIteration):
            next(i)
