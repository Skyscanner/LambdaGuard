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
from lambdaguard.utils.arnparse import arnparse
from lambdaguard.utils.log import debug
from lambdaguard.core.AWS import AWS
from lambdaguard.core.Role import Role
from lambdaguard.core.KMS import KMS
from lambdaguard.security.Scan import Scan


class Lambda(AWS):
    def __init__(self, arn, *args, **kwargs):
        super().__init__(arn, args[0].profile, args[0].keys[0], args[0].keys[1])

        self.args = args[0]
        self.identity = args[1]
        self.runtime = None
        self.handler = None
        self.layers = None
        self.description = None
        self.role = None
        self.kms = None
        self.codeURL = None
        self.writes = {'count': 0, 'items': {}}
        self.triggers = {'services': [], 'items': {}}
        self.resources = {'services': [], 'items': {}}
        self.security = {'count': {}, 'items': {}}

        self.get_function()
        self.get_policy()
        self.get_triggers()
        self.get_resources()
        self.get_security()

    def get_policy(self):
        '''
        Fetches Function (Resource-based) policy
        '''
        try:
            policy = self.client.get_policy(FunctionName=self.arn.resource)
            self.policy = json.loads(policy['Policy'])
        except Exception:
            debug(self.arn.full)

    def get_function(self):
        '''
        Fetches Lambda function configuration
        '''
        try:
            if self.identity.acl.allowed("lambda:GetFunction"):
                function = self.client.get_function(
                    FunctionName=self.arn.resource
                )
                config = function['Configuration']
                self.codeURL = function['Code']['Location']
            elif self.identity.acl.allowed("lambda:GetFunctionConfiguration"):
                config = self.client.get_function_configuration(
                    FunctionName=self.arn.resource
                )
                self.codeURL = ''
            else:
                exit("\nMissing both lambda:GetFunction and lambda:GetFunctionConfiguration")

            self.runtime = config['Runtime']
            self.handler = config['Handler']
            self.description = config['Description']
            if 'KMSKeyArn' in config:
                self.kms = KMS(
                    config['KMSKeyArn'],
                    profile=self.profile,
                    access_key_id=self.access_key_id,
                    secret_access_key=self.secret_access_key
                )
            self.role = Role(
                config['Role'],
                profile=self.profile,
                access_key_id=self.access_key_id,
                secret_access_key=self.secret_access_key
            )
            self.layers = []
            if 'Layers' in config:
                for layer in config['Layers']:
                    layer = self.client.get_layer_version_by_arn(Arn=layer['Arn'])
                    self.layers.append({
                        'arn': layer['LayerVersionArn'],
                        'description': layer['Description'],
                        'codeURL': layer['Content']['Location']
                    })
        except Exception:
            debug(self.arn.full)

    def get_triggers(self):
        '''
        Tracks events that trigger the Lambda function
        '''
        # Collect triggers from Event Sources
        try:
            eventSource = self.client.list_event_source_mappings(
                FunctionName=self.arn.resource
            )['EventSourceMappings']

            for event in eventSource:
                if event['State'] != 'Enabled':
                    continue

                self.triggers['items'][event['EventSourceArn']] = ['lambda:InvokeFunction']

                # Track services
                self.triggers['services'].append(arnparse(event['EventSourceArn']).service)
        except Exception:
            debug(self.arn.full)

        # Collect triggers from Function policy
        try:
            if self.policy:
                for statement in self.policy['Statement']:
                    if 'Condition' in statement:
                        if 'ArnLike' in statement['Condition']:
                            if 'AWS:SourceArn' in statement['Condition']['ArnLike']:
                                arn = statement['Condition']['ArnLike']['AWS:SourceArn']

                                if type(statement['Action']) == str:
                                    self.triggers['items'][arn] = [statement['Action']]
                                else:
                                    self.triggers['items'][arn] = statement['Action']

                                # Track services
                                self.triggers['services'].append(arnparse(arn).service)
        except Exception:
            debug(self.arn.full)

        self.triggers['services'] = list(set(self.triggers['services']))

    def get_resources(self):
        '''
        Tracks resources used by the Lambda function
        '''
        try:
            if self.role:
                for policy in self.role.policy['policies']:
                    for statement in policy['document']['Statement']:
                        if type(statement) != dict:
                            continue
                        if statement['Effect'] != 'Allow':
                            continue

                        if type(statement['Resource']) == str:
                            arns = [statement['Resource']]
                        else:
                            arns = statement['Resource']

                        if type(statement['Action']) == str:
                            actions = [statement['Action']]
                        else:
                            actions = statement['Action']

                        # Track services
                        for action in actions:
                            self.resources['services'].append(
                                action.split(':')[0]
                            )

                        # Track actions by resource
                        for arn in arns:
                            if arn in self.resources['items']:
                                self.resources['items'][arn] = list(
                                    set(self.resources['items'][arn] + actions)
                                )
                            else:
                                self.resources['items'][arn] = actions

            self.resources['services'] = list(set(self.resources['services']))
        except Exception:
            debug(self.arn.full)

    def get_security(self):
        try:
            self.security = Scan(
                self.report(),
                self.args
            ).security
        except Exception:
            debug(self.arn.full)

    def set_writes(self, writes):
        try:
            self.writes['count'] += 1
            for arn, policy in writes.items():
                self.writes['items'][arn] = policy
        except Exception:
            debug(self.arn.full)

    def report(self):
        ret = {
            'arn': self.arn.full,
            'name': self.arn.resource,
            'description': self.description,
            'region': self.arn.region,
            'runtime': self.runtime,
            'handler': self.handler,
            'layers': self.layers,
            'codeURL': self.codeURL,
            'role': self.role.arn.full,
            'policy': {
                'function': self.policy,
                'role': self.role.policy
            },
            'writes': self.writes,
            'triggers': self.triggers,
            'resources': self.resources,
            'security': self.security
        }
        if self.kms:
            ret['kms'] = self.kms.arn.full
            ret['policy']['kms'] = self.kms.policies
        return ret
