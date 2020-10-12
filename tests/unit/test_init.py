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

from lambdaguard import get_regions
from lambdaguard.utils.cli import parse_args


class Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixtures = Path(__file__).parents[2].joinpath("fixtures")

    def test_get_regions(self):
        # All regions
        args = parse_args("-r all")
        regions = get_regions(args)
        self.assertEqual(len(regions), 20)
        # List of regions
        args = parse_args("-r eu-west-1,ap-east-1")
        regions = get_regions(args)
        self.assertEqual(len(regions), 2)
        self.assertIn("eu-west-1", regions)
        self.assertIn("ap-east-1", regions)
        # Single region
        args = parse_args("-r ap-east-1")
        regions = get_regions(args)
        self.assertEqual(regions, ["ap-east-1"])
        # Invalid regions
        with self.assertRaises(ValueError):
            args = parse_args("-r test")
            args.region = None
            get_regions(args)
        with self.assertRaises(ValueError):
            args = parse_args("-r test")
            args.region = ""
            get_regions(args)
        with self.assertRaises(ValueError):
            get_regions(parse_args("-r test"))
