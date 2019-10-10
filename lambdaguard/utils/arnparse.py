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


class ARN(object):
    def __init__(self, full, partition, service, region, account_id, resource_type, resource):
        self.full = full
        self.partition = partition
        self.service = service
        self.region = region
        self.account_id = account_id
        self.resource_type = resource_type
        self.resource = resource


def empty_str_to_none(str_):
    if str_ == '':
        return None
    return str_


def arnparse(arn_str):
    # https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html
    if not arn_str.startswith('arn:'):
        return None

    elements = arn_str.split(':', 5)
    elements += [''] * (6 - len(elements))

    resource = elements[5].split('/')[-1]
    resource_type = None

    service = elements[2]
    if service == 'execute-api':
        service = 'apigateway'

    if service not in ['sns', 'apigateway']:
        if service == 'dynamodb':
            resource_type = elements[5].split('/')[0]  # table
            if len(elements[5].split('/')) > 1:
                resource = elements[5].split('/')[1]  # table name
        elif service == 's3':
            if len(elements[5].split('/')) > 1:
                resource_type = elements[5].split('/', 1)[1]  # objects
            resource = elements[5].split('/')[0]  # bucket name
        elif service == 'kms':
            resource_type = elements[5].split('/')[0]
        elif '/' in resource:
            resource_type, resource = resource.split('/', 1)
        elif ':' in resource:
            resource_type, resource = resource.split(':', 1)

    return ARN(
        full=arn_str,
        partition=elements[1],
        service=service,
        region=empty_str_to_none(elements[3]),
        account_id=empty_str_to_none(elements[4]),
        resource_type=resource_type,
        resource=resource,
    )
