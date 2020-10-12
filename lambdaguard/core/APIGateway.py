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

from lambdaguard.core.AWS import AWS
from lambdaguard.utils.log import debug


class APIGateway(AWS):
    def __init__(self, arn, profile=None, access_key_id=None, secret_access_key=None):
        super().__init__(arn, profile, access_key_id, secret_access_key)

        self.rest_api_id = ""
        self.endpoint = ""
        self.stages = []
        self.resources = []

        self.get_api()

        self.info = f"REST API ID: {self.rest_api_id}"

    def get_api(self):
        self.rest_api_id = self.arn.full.split(":")[-1].split("/")[0]
        self.endpoint = f"https://{self.rest_api_id}.execute-api.{self.arn.region}.amazonaws.com"

        try:
            rest_api = self.client.get_rest_api(restApiId=self.rest_api_id)
            if "policy" in rest_api:
                self.policy = json.loads(rest_api["policy"].replace("\\", ""))
        except Exception:
            debug(self.arn.full)

        try:
            for item in self.client.get_stages(restApiId=self.rest_api_id)["item"]:
                self.stages.append(item["stageName"])
        except Exception:
            debug(self.arn.full)

        try:
            for item in self.client.get_resources(restApiId=self.rest_api_id)["items"]:
                if "resourceMethods" in item:
                    for http_method in item["resourceMethods"]:
                        method = self.client.get_method(
                            restApiId=self.rest_api_id,
                            resourceId=item["id"],
                            httpMethod=http_method,
                        )
                        self.resources.append(
                            {
                                "id": item["id"],
                                "method": http_method,
                                "path": item["path"],
                                "apiKeyRequired": method["apiKeyRequired"],
                                "authorizationType": method["authorizationType"],
                            }
                        )
        except Exception:
            debug(self.arn.full)
