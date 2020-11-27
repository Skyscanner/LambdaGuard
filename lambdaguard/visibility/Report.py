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

from lambdaguard.utils.arnparse import arnparse


class VisibilityReport:
    def __init__(self, reports_path: str):
        self.reports = Path(reports_path)
        self.index = {}
        self.reports.joinpath("reports").mkdir(parents=True, exist_ok=True)

    def save(self, report, verbose=False):
        self._save_assets(report)
        idx = md5()
        idx.update(report["arn"].encode("utf-8"))
        idx = idx.hexdigest()
        self.index[idx] = report["arn"]
        report = json.dumps(report, indent=4)
        with self.reports.joinpath("reports", f"{idx}.json").open("w") as f:
            f.write(report)
        if verbose:
            print(report)
        self._save_index()

    def _save_index(self):
        with self.reports.joinpath("index.json").open("w") as f:
            f.write(json.dumps(self.index, indent=4))

    def _save_assets(self, report):
        assetsfile = self.reports.joinpath("assets.json")
        assets = []
        if assetsfile.exists():
            assets = json.loads(assetsfile.read_text())
        assets += self._get_assets(report)
        assets = list(set(assets))
        assetsfile.write_text(json.dumps(assets, indent=4))

    def _get_assets(self, report):
        assets = []
        items = list(report["triggers"]["items"].keys())
        items += list(report["resources"]["items"].keys())
        for item in items:
            try:
                arnparse(item)
                assets.append(item)
            except Exception:
                continue
        assets = list(set(assets))
        return assets
