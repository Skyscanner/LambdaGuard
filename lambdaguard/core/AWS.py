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
import functools
import boto3

from lambdaguard.utils.arnparse import arnparse

@functools.lru_cache()
def get_AWS_client(profile_name, aws_access_key_id, aws_secret_access_key, region_name, service):
    session = boto3.Session(profile_name=profile_name)
    return session.client(
        service,
        region_name=region_name,
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
    )

class AWS(object):
    """
    Base AWS service object extended by each individual service class.
    """

    def __init__(self, arn, profile=None, access_key_id=None, secret_access_key=None):
        # AWS ARN
        self.arn = arnparse(arn)

        # AWS Profile and Keys
        self.profile = profile
        self.access_key_id = access_key_id
        self.secret_access_key = secret_access_key

        # AWS Resource-based policy
        self.policy = {}

        # Additional service information
        self.info = ""

        # AWS connection
        self.client = get_AWS_client(
            self.profile,
            access_key_id,
            secret_access_key,
            self.arn.region,
            self.arn.service,
        )
