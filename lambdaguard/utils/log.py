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
import logging
import traceback
from sys import exc_info
from botocore.exceptions import ClientError
from pathlib import Path


def configure_log(path=''):
    logfile = Path(path, 'lambdaguard.log')
    logging.basicConfig(
        level=logging.WARNING,
        format='[%(asctime)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M',
        filename=logfile,
        filemode='w'
    )


def log(data):
    logging.warning(data)


def debug(arn):
    exc_type, exc_value, exc_traceback = exc_info()
    exc_value = str(exc_value)
    trace = traceback.format_exc()
    if trace == 'NoneType: None\n':
        return None  # Empty
    elif exc_type == ClientError:
        if 'arn:aws:lambda:::awslayer:' in exc_value:
            return None  # Update opt-in/out
    elif exc_type == ValueError:
        if 'Invalid endpoint:' in exc_value:
            return None  # Invalid resource configuration
    logging.error(f'[{arn}]\n{trace}')
    return trace
