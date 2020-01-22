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


class PrivilegeEscalation:
    def __init__(self, item):
        self.item = item

    def audit(self):
        exploitable = []
        iam = [
            'iam:*',
            'iam:AddUserToGroup',
            'iam:AttachGroupPolicy',
            'iam:AttachRolePolicy',
            'iam:AttachUserPolicy',
            'iam:CodeStarCreateProjectFromTemplate',
            'iam:CodeStarCreateProjectThenAssociateTeamMember',
            'iam:CreateAccessKey',
            'iam:CreateEC2WithExistingIP',
            'iam:CreateLoginProfile',
            'iam:CreateNewPolicyVersion',
            'iam:EditExistingLambdaFunctionWithRole',
            'iam:PassExistingRoleToNewCloudFormation',
            'iam:PassExistingRoleToNewCodeStarProject',
            'iam:PassExistingRoleToNewDataPipeline',
            'iam:PassExistingRoleToNewGlueDevEndpoint',
            'iam:PassExistingRoleToNewLambdaThenInvoke',
            'iam:PassExistingRoleToNewLambdaThenTriggerWithExistingDynamo',
            'iam:PassExistingRoleToNewLambdaThenTriggerWithNewDynamo',
            'iam:PutGroupPolicy',
            'iam:PutRolePolicy',
            'iam:PutUserPolicy',
            'iam:SetExistingDefaultPolicyVersion',
            'iam:UpdateExistingGlueDevEndpoint',
            'iam:UpdateLoginProfile',
            'iam:UpdateRolePolicyToAssumeIt'
        ]

        for action in self.item:
            if action in iam:
                exploitable.append(action)

        if len(exploitable):
            exploitable = ', '.join(exploitable)
            yield {
                'level': 'high',
                'text': f'Potential privilege escalation via the following Actions: {exploitable}'
            }
