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
from sys import argv

from lambdaguard.utils.cli import align, green, parse_args


class Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixtures = Path(__file__).parents[2].joinpath("fixtures")

    def test_parse_args(self):
        # Reset sys.argv
        exe = argv[0]
        argv.clear()
        argv.append(exe)
        # No arguments - default values
        args = parse_args()
        self.assertIsNone(args.function)
        self.assertIsNone(args.input)
        self.assertEqual(args.output, "lambdaguard_output")
        self.assertIsNone(args.profile)
        self.assertEqual(args.keys, [None, None])
        self.assertEqual(args.region, "all")
        self.assertIsNone(args.sonarqube)
        self.assertFalse(args.verbose)
        self.assertFalse(args.html)
        # Parse custom arguments
        args = parse_args("-o output -v -f function -k id secret")
        self.assertEqual(args.output, "output")
        self.assertEqual(args.function, "function")
        self.assertEqual(args.keys, ["id", "secret"])
        self.assertTrue(args.verbose)

    def test_align(self):
        expected = "\r          \x1b[0;32mkey............ value\x1b[0m"
        self.assertEqual(align("key", "value", green), expected)
