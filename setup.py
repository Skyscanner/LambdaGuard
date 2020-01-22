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
from setuptools import setup, find_packages
from pathlib import Path


def get_version():
    ret = {}
    code = Path(__file__).parent.joinpath('lambdaguard', '__version__.py')
    exec(code.read_text(), ret)
    return ret['__version__']


long_description = '''
LambdaGuard is an AWS Serverless Security auditing tool designed to create asset visibility 
and provide actionable results. It provides a meaningful overview in terms of 
statistical analysis, AWS service dependencies and configuration checks from 
the security perspective.

https://github.com/Skyscanner/LambdaGuard
'''

install_requires=[
    'boto3',
    'argparse',
    'requests'
]

dev_requires = [
    'coverage~=4.4',
    'flake8>=2.5.4',
    'pytest>=2.9.1',
    'pytest-mock>=1.0',
    'pip-tools',
    'wheel',
    'twine'
]

setup(
    name='LambdaGuard',
    version=get_version(),
    author='Artëm Tsvetkov',
    author_email='artem.tsvetkov@skyscanner.net',
    description='LambdaGuard',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/Skyscanner/LambdaGuard',
    packages=find_packages(),
    include_package_data=True,
    # classifiers=[
    #     'Programming Language :: Python :: 3.6.3'
    # ],
    python_requires='>=3.6.3',
    setup_requires=['pytest-runner'],
    install_requires=install_requires,
    tests_require=dev_requires,
    extras_require={
        'dev': dev_requires,
    },
    entry_points={
        'console_scripts': ['lambdaguard=lambdaguard:run'],
    }
)
