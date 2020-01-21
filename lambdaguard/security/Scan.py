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
from lambdaguard.utils.arnparse import arnparse
from lambdaguard.utils.log import debug
from lambdaguard.core.S3 import S3
from lambdaguard.core.SQS import SQS
from lambdaguard.core.SNS import SNS
from lambdaguard.core.APIGateway import APIGateway
from lambdaguard.core.DynamoDB import DynamoDB
from lambdaguard.core.KMS import KMS
from lambdaguard.security.PolicyStatement import PolicyStatement
from lambdaguard.security.AccessControlList import AccessControlList
from lambdaguard.security.Encryption import Encryption
from lambdaguard.security.Public import Public
from lambdaguard.security.SonarQube import SonarQube


class Scan:
    def __init__(self, report, *args, **kwargs):
        self.report = report
        self.args = args[0]
        self.profile = args[0].profile
        self.access_key_id = args[0].keys[0]
        self.secret_access_key = args[0].keys[1]
        self.security = {'count': {}, 'items': []}

        self.item = None  # item currently scanned

        if self.args.sonarqube:
            try:
                self.sonarqube = SonarQube(self.args.sonarqube, self.args.output)
            except Exception:
                debug('Invalid SonarQube configuration')
                self.args.sonarqube = None  # disable SonarQube

        self.scan()

    def track(self, arn, item):
        '''
        Example: track('arn:...', {'level':'high','text':'...'})

        @param  idx     Index in Statistics dictionary
        @param  value   Value
        '''
        item['where'] = arn
        if self.item:
            item['where'] += f'\n\n{self.item.info}'

        if item in self.security['items']:
            return  # Avoid duplicates

        level = item['level']
        if level in self.security['count']:
            self.security['count'][level] += 1
        else:
            self.security['count'][level] = 1

        self.security['items'].append(item)

    def scan(self):
        '''
        Scan Lambda report for vulnerabilities
        and provide recommendations.
        '''
        # Audit Function policy
        if not self.report['policy']['function']:
            self.track(self.report['arn'], {
                'level': 'info',
                'text': 'Function policy is not defined'
            })
        else:
            if 'Statement' in self.report['policy']['function']:
                for statement in self.report['policy']['function']['Statement']:
                    for _ in PolicyStatement(statement).audit():
                        self.track(self.report['arn'], _)

        # Audit Execution role policy
        if not len(self.report['policy']['role']['policies']):
            self.track(self.report['arn'], {
                'level': 'info',
                'text': 'Execution Role policy is not defined'
            })
        else:
            for policy in self.report['policy']['role']['policies']:
                if 'Statement' in policy['document']:
                    for statement in policy['document']['Statement']:
                        for _ in PolicyStatement(statement, policy=policy).audit():
                            self.track(self.report['role'], _)

        # Audit KMS
        if 'kms' in self.report:
            self.item = KMS(
                self.report['kms'],
                profile=self.profile,
                access_key_id=self.access_key_id,
                secret_access_key=self.secret_access_key
            )
            if not self.item.rotation:
                self.track(self.report['kms'], {
                    'level': 'medium',
                    'text': 'Automatic rotation of key material is disabled\nhttps://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html'
                })
            for _, policy in self.item.policies.items():
                self.audit_policy_statements(self.item.arn, policy)

        # Audit Resources
        if 'logs' not in self.report['resources']['services']:
            self.track(self.report['arn'], {
                'level': 'low',
                'text': 'Function activity is not monitored by CloudWatch due to missing logs permissions'
            })

        # Audit Triggers and Resources
        items = list(set(
            list(self.report['triggers']['items'].keys()) +
            list(self.report['resources']['items'].keys())
        ))
        for arn in items:
            if arn == '*':
                continue

            arn = arnparse(arn)
            if arn.resource in ['*', '']:
                continue

            self.item = None
            if arn.service == 's3':
                if arn.resource_type:  # S3 object path
                    continue
                self.item = S3(
                    arn.full,
                    profile=self.profile,
                    access_key_id=self.access_key_id,
                    secret_access_key=self.secret_access_key
                )
                for _ in AccessControlList(self.item.acl).audit():
                    self.track(arn.full, _)
                for _ in Encryption(self.item).audit():
                    self.track(arn.full, _)
            elif arn.service == 'sqs':
                self.item = SQS(
                    arn.full,
                    profile=self.profile,
                    access_key_id=self.access_key_id,
                    secret_access_key=self.secret_access_key
                )
            elif arn.service == 'sns':
                self.item = SNS(
                    arn.full,
                    profile=self.profile,
                    access_key_id=self.access_key_id,
                    secret_access_key=self.secret_access_key
                )
            elif arn.service == 'apigateway':
                self.item = APIGateway(
                    arn.full,
                    profile=self.profile,
                    access_key_id=self.access_key_id,
                    secret_access_key=self.secret_access_key
                )
            elif arn.service == 'dynamodb':
                self.item = DynamoDB(
                    arn.full,
                    profile=self.profile,
                    access_key_id=self.access_key_id,
                    secret_access_key=self.secret_access_key
                )
            elif arn.service == 'kms':
                self.item = KMS(
                    arn.full,
                    profile=self.profile,
                    access_key_id=self.access_key_id,
                    secret_access_key=self.secret_access_key
                )

            if self.item:
                if type(self.item) == KMS:
                    # Audit KMS Policies
                    for _, policy in self.item.policies.items():
                        self.audit_policy_statements(self.item.arn, policy)
                else:
                    # Audit item Resource-based Policy
                    self.audit_policy_statements(self.item.arn, self.item.policy)
                    # If policy is missing, then the service is public
                    for _ in Public(self.item).audit():
                        self.track(arn.full, _)

        # SonarQube
        if self.args.sonarqube:
            self.scan_sonarqube(
                arn,
                self.report['codeURL'],
                self.report['runtime']
            )
            for layer in self.report['layers']:
                self.scan_sonarqube(
                    arn,
                    layer['codeURL'],
                    self.report['runtime']
                )

        # Sort findings by level
        sorted_items = []
        for sort in ['high', 'medium', 'low', 'info']:
            for item in self.security['items']:
                if item['level'] == sort:
                    if item not in sorted_items:
                        sorted_items.append(item)
        self.security['items'] = sorted_items

    def audit_policy_statements(self, arn, policy):
        if 'Statement' in policy:
            for statement in policy['Statement']:
                for _ in PolicyStatement(statement).audit():
                    self.track(arn.full, _)

    def scan_sonarqube(self, arn, codeURL, runtime):
        for _ in self.sonarqube.scan(codeURL, runtime):
            self.track(arn.full, _)
