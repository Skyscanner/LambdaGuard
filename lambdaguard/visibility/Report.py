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
from hashlib import md5
from pathlib import Path


class VisibilityReport:
    def __init__(self, path):
        self.path = Path(path)
        self.index = {}

        self.path.joinpath("reports").mkdir(parents=True, exist_ok=True)

    def save(self, report, verbose=False):
        idx = md5()
        idx.update(report["arn"].encode("utf-8"))
        idx = idx.hexdigest()

        self.index[idx] = report["arn"]

        report = json.dumps(report, indent=4)
        with self.path.joinpath("reports", f"{idx}.json").open("w") as f:
            f.write(report)
        if verbose:
            print(report)

        self.save_index()

    def save_index(self):
        with self.path.joinpath("index.json").open("w") as f:
            f.write(json.dumps(self.index, indent=4))
