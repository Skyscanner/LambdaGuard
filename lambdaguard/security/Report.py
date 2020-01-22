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


class SecurityReport:
    def __init__(self, path):
        self.path = Path(path)

    def save(self):
        if not self.path.joinpath('index.json').exists():
            return

        OUT = []

        index = json.loads(
            self.path.joinpath('index.json').read_text()
        )

        for sort in ['high', 'medium', 'low', 'info']:
            for idx, lmbd_arn in index.items():
                with self.path.joinpath('reports', f'{idx}.json').open() as f:
                    report = json.loads(f.read())
                    if 'items' in report['security']:
                        for _ in report['security']['items']:
                            if _['level'] == sort:
                                OUT.append({
                                    'index': idx,
                                    'lambda': lmbd_arn,
                                    'where': _['where'],
                                    'level': _['level'],
                                    'text': _['text']
                                })

        with self.path.joinpath('security.json').open('w') as f:
            f.write(json.dumps(OUT, indent=4))
