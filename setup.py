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
import setuptools
from pathlib import Path


version = Path('lambdaguard/version.txt').read_text()
long_description = '''
LambdaGuard is an AWS Serverless Security auditing tool designed to create asset visibility 
and provide actionable results. It provides a meaningful overview in terms of 
statistical analysis, AWS service dependencies and configuration checks from 
the security perspective.

https://github.com/Skyscanner/lambdaguard
'''

dev_requires = [
    'pytest==3.6.0',
    'flake8>=3.3.0',
    'pytest-cov>=2.5.1',
    'pip-tools==2.0.2'
]

setuptools.setup(
    name='lambdaguard',
    version=version,
    author='Artëm Tsvetkov',
    author_email='artem.tsvetkov@skyscanner.net',
    description='LambdaGuard',
    long_description=long_description,
    long_description_content_type="text/markdown",
    url='https://github.com/Skyscanner/LambdaGuard',
    packages=setuptools.find_packages(),
    include_package_data=True,
    install_requires=[
        'boto3',
        'argparse',
        'requests'
    ],
    extras_require={
        'dev': dev_requires,
    },
    scripts=['bin/lambdaguard']
)
