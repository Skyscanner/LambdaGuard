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

from lambdaguard.utils.paginator import paginate


class Client:
    """
    Mock AWS client
    """

    def __init__(self, marker=None):
        self.marker = marker

    def get_paginator(self, paginator):
        return Paginator(self.marker)


class Paginator:
    """
    Mock AWS paginator
    """

    def __init__(self, marker=None):
        self.marker = marker

    def paginate(self, **kwargs):
        if self.marker:
            yield {"Page": {}, "NextMarker": self.marker}
            self.marker = None
            yield from self.paginate()
        else:
            yield {"Page": {}}


class Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixtures = Path(__file__).parents[2].joinpath("fixtures")

    def test_paginate(self):
        # Single page
        pages = paginate(Client(), None)
        self.assertEqual(next(pages), {"Page": {}})
        with self.assertRaises(StopIteration):
            next(pages)
        # Multiple pages
        pages = paginate(Client("multiple"), None)
        self.assertEqual(next(pages), {"Page": {}, "NextMarker": "multiple"})
        self.assertEqual(next(pages), {"Page": {}})
        with self.assertRaises(StopIteration):
            next(pages)
