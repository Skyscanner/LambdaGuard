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
from os import chdir as cd
from pathlib import Path
from re import sub
from shlex import split as shsplit
from shutil import rmtree
from subprocess import DEVNULL, check_call as sh
from time import sleep
from zipfile import ZipFile, is_zipfile

import requests

SONAR_PROJECT_PROPERTIES = """
sonar.host.url={}
sonar.login={}
sonar.password={}
sonar.language={}
sonar.projectKey={}
sonar.projectName={}
sonar.sourceEncoding=UTF-8
sonar.sources=.
sonar.java.binaries=.
sonar.tests=
"""


class SonarQube:
    def __init__(self, config, output):
        self.downloads = Path(output, "downloads")
        self.downloads.mkdir(parents=True, exist_ok=True)
        config = Path(config)
        if config.exists():
            self.config = json.loads(config.read_text())
        else:
            raise FileNotFoundError("SonarQube config file not found: {}".format(config))

    def __del__(self):
        rmtree(self.downloads, ignore_errors=True)

    def scan(self, project_name, codeURL, runtime):
        if not self.config:
            return  # invalid config
        zippath = self.downloads.joinpath("lambda.zip")
        zippath.write_bytes(requests.get(codeURL).content)
        if not is_zipfile(zippath):
            return  # invalid zip
        zf = ZipFile(zippath)

        # Unzip Lambda source code
        for _ in zf.namelist():
            zf.extractall(self.downloads, members=[_])

        # Configure sonar-project.properties
        if runtime.startswith("node"):
            language = "js"
        else:
            language = sub(r"[^a-z]", "", runtime.lower())
        Path(self.downloads, "sonar-project.properties").write_text(
            SONAR_PROJECT_PROPERTIES.format(
                self.config["url"],
                self.config["login"],
                self.config["password"],
                language,
                project_name,
                project_name,
            )
        )

        # Run sonar-scanner
        cwd = Path(".").resolve()
        cd(self.downloads)
        sh(shsplit("git init"), stdout=DEVNULL, stderr=DEVNULL)
        sh(shsplit(self.config["command"]), stdout=DEVNULL, stderr=DEVNULL)
        cd(cwd)
        rmtree(self.downloads, ignore_errors=True)
        self.downloads.mkdir(parents=True, exist_ok=True)

        # Get results
        curl = requests.Session()
        curl.auth = (self.config["login"], self.config["password"])

        while True:
            sleep(3)
            task = json.loads(curl.get(f'{self.config["url"]}/api/ce/activity').text)["tasks"][0]
            if task["status"] in ["SUCCESS", "FAIL"]:
                break

        issues = json.loads(curl.get(f'{self.config["url"]}/api/issues/search?project={project_name}').text)["issues"]
        curl.post(f'{self.config["url"]}/api/projects/delete', data={"project": project_name})

        for issue in issues:
            if issue["status"] != "OPEN":
                continue
            where = issue["component"].split(":", 1)[1]
            yield {
                "level": "high",
                "text": f'{issue["message"]}\n{where} on line {issue["textRange"]["startLine"]}.',
            }
