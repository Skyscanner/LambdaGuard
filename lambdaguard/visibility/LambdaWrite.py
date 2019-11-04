"""
Copyright 2019 Skyscanner Ltd

Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.
"""


import boto3
import json
from pathlib import Path
from lambdaguard.utils.arnparse import arnparse
from lambdaguard.utils.iterator import iterate
from lambdaguard.utils.paginator import paginate


def is_write_action(action):
    return action in [
        '*',
        'lambda:*',
        'lambda:Create*',
        'lambda:Delete*',
        'lambda:Invoke*',
        'lambda:Publish*',
        'lambda:Put*',
        'lambda:Tag*',
        'lambda:Untag*',
        'lambda:Update*',
        'lambda:CreateAlias',
        'lambda:CreateFunction',
        'lambda:DeleteAlias',
        'lambda:DeleteEventSourceMapping',
        'lambda:DeleteFunction',
        'lambda:DeleteFunctionConcurrency',
        'lambda:DeleteLayerVersion',
        'lambda:InvokeAsync',
        'lambda:InvokeFunction',
        'lambda:PublishLayerVersion',
        'lambda:PublishVersion',
        'lambda:PutFunctionConcurrency',
        'lambda:TagResource',
        'lambda:UntagResource',
        'lambda:UpdateAlias',
        'lambda:UpdateEventSourceMapping',
        'lambda:UpdateFunctionCode',
        'lambda:UpdateFunctionConfiguration'
    ]


class LambdaWrite:
    """
    This is a class for tracking attached IAM policies
    that have Lambda Write permissions
    """
    def __init__(self, args):
        self.args = args
        self.writes = {}

        for policy_arn, policy in self.get_attached_local_policies():
            for _ in self.parse(policy):
                self.writes.update({
                    _['lambda']: {
                        policy_arn: _['actions']
                    }
                })

        self.save()
        import json
        print(json.dumps(self.writes, indent=4))
        exit(0)

    def get_attached_local_policies(self):
        client = boto3.Session(
            profile_name=self.args.profile,
            aws_access_key_id=self.args.keys[0],
            aws_secret_access_key=self.args.keys[1],
            region_name=self.args.region
        ).client('iam')
        pages = paginate(
            client,
            'list_policies',
            Scope='Local',
            OnlyAttached=True
        )
        for page in pages:
            for policy in page['Policies']:
                version = client.get_policy_version(
                    PolicyArn=policy['Arn'],
                    VersionId=policy['DefaultVersionId']
                )['PolicyVersion']
                yield policy['Arn'], version

    def parse(self, policy):
        for statement in policy['Document']['Statement']:
            # Skip if not Allow
            if statement['Effect'] != 'Allow':
                continue

            # Identify all write Actions
            write_actions = []
            for action in iterate(statement['Action']):
                if not is_write_action(action):
                    continue
                write_actions.append(action)
            if not write_actions:
                return None

            # Return all write Actions per Resource
            for resource in iterate(statement['Resource']):
                yield {
                    'lambda': resource,
                    'actions': write_actions
                }

    def save(self):
        Path(self.args.output, 'writes.json').write_text(
            json.dumps(self.writes, indent=4)
        )