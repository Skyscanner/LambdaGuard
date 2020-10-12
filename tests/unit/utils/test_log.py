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
import logging
import unittest
from pathlib import Path

from lambdaguard.utils.log import configure_log, debug


class Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixtures = Path(__file__).parents[2].joinpath("fixtures")
        cls.logpath = "/tmp/lambdaguard.log"

    def test_configure_log(self):
        configure_log("/tmp")
        logger = logging.getLogger()
        # Root logger level
        self.assertEqual(logger.getEffectiveLevel(), logging.WARNING)
        # Log file
        self.assertEqual(logger.handlers[0].baseFilename, self.logpath)
        # Overwrite file
        self.assertEqual(logger.handlers[0].mode, "w")
        # LambdaGuard logger level
        self.assertEqual(logger.handlers[0].level, logging.DEBUG)

    def test_debug(self):
        configure_log("/tmp")

        # Called without an exception to handle
        self.assertEqual(debug(), None)

        # Logging critical errors
        try:
            1 / 0
        except Exception:
            trace = debug().strip().split("\n")
            etype, evalue = trace[-1].split(": ", 1)
            self.assertEqual(etype, "ZeroDivisionError")
            self.assertEqual(evalue, "division by zero")

            elog = Path(self.logpath).read_text().strip()
            elog.endswith("ZeroDivisionError: division by zero")
