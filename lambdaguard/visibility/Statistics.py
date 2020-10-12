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
from pathlib import Path

from lambdaguard.utils.arnparse import arnparse


class Statistics:
    def __init__(self, path):
        self.path = Path(path)
        self.statistics = {
            "lambdas": 0,
            "layers": 0,
            "regions": {"count": 0, "items": {}},
            "runtimes": {"count": 0, "items": {}},
            "triggers": {"count": 0, "items": {}},
            "resources": {"count": 0, "items": {}},
            "security": {"count": 0, "items": {}},
        }

    def track(self, idx, value, count=1):
        """
        Tracks number of occurences of a given value
        under a given Statistics dictionary index.
        Optionally, specify how many occurences to count.
        Example: track('runtime', 'python3.7')

        @param  idx     Index in Statistics dictionary
        @param  value   Value
        """
        self.statistics[idx]["count"] += count

        if value not in self.statistics[idx]["items"]:
            self.statistics[idx]["items"][value] = count
        else:
            self.statistics[idx]["items"][value] += count

    def parse(self, report, verbose=False):
        """
        Parses Lambda report and automatically extracts and
        tracks statistics.
        """
        self.statistics["lambdas"] += 1
        self.statistics["layers"] += len(report["layers"])
        self.track("regions", report["region"])
        self.track("runtimes", report["runtime"])
        for idx in ["triggers", "resources"]:
            for arn in report[idx]["items"]:
                if arn == "*":
                    continue
                self.track(idx, arnparse(arn).service)
        if "count" in report["security"]:
            for level, level_count in report["security"]["count"].items():
                self.track("security", level, level_count)

        self.save(verbose=verbose)

    def save(self, verbose=False):
        stats = json.dumps(self.statistics, indent=4)
        with self.path.joinpath("statistics.json").open("w") as f:
            f.write(stats)
        if verbose:
            print(stats)
