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
import argparse
from os import environ
from lambdaguard.__version__ import __version__


environ['PYTHONIOENCODING'] = 'UTF-8'


orange = '\033[3;33m'
green = '\033[0;32m'
nocolor = '\033[0m'

header = orange + f'''
         `.::////::.`
      ./osssssoossssso/.
    -osss/-`      .-/ssso-
  `osso-  .++++:      -osso`
 `oss/    .//oss-       /sss`
 +ss+        -sss.       /sso
.sss`       .sssso`      `sss.   LambdaGuard v{__version__}
-sso       :ssooss+       oss-
.sss`     /ss+``oss/     `sss.
 +ss+   `oss/   .sss///  /sso
 `oss/`.oso-     -ssso+./sso`
  `+sso:          .`  -oss+`
    -osss+-.`    `.-+ssso-
      ./osssssssssssso/.
         `.-:////:-.`''' + nocolor

author = f'\033[3;32mDeveloped by Artëm Tsvetkov{green}'


def parse_args(arguments=''):
    argsParser = argparse.ArgumentParser(
        description=author,
        usage=header,
        epilog=nocolor
    )
    inputArgs = argsParser.add_mutually_exclusive_group()
    inputArgs.add_argument(
        '-f',
        '--function',
        default=None,
        help='Lambda ARN'
    )
    inputArgs.add_argument(
        '-i',
        '--input',
        default=None,
        help='Input file with a list of ARNs'
    )
    argsParser.add_argument(
        '-o',
        '--output',
        default='lambdaguard_output',
        help='Output directory'
    )
    argsParser.add_argument(
        '-H',
        '--html',
        action='store_true',
        help='Generate HTML report and quit'
    )
    awsArgs = argsParser.add_mutually_exclusive_group()
    awsArgs.add_argument(
        '-p',
        '--profile',
        default=None,
        help='AWS profile'
    )
    awsArgs.add_argument(
        '-k',
        '--keys',
        nargs=2,
        metavar=('ID', 'SECRET'),
        default=[None, None],
        help='AWS keys: AccessKeyId SecretAccessKey'
    )
    argsParser.add_argument(
        '-r',
        '--region',
        default='eu-west-1',
        help='AWS region'
    )
    argsParser.add_argument(
        '-sq',
        '--sonarqube',
        help='SonarQube config file'
    )
    argsParser.add_argument(
        '-v',
        '--verbose',
        action='store_true',
        help='Verbose output to terminal'
    )
    argsParser.add_argument(
        '-V',
        '--version',
        action='version',
        version=__version__,
        help='Display current version'
    )

    if len(arguments):
        args = argsParser.parse_known_args(arguments.split())[0]
    else:
        args = argsParser.parse_known_args()[0]

    return args


def align(key, value, color=green):
    ret = (
        ' ' * 10 +
        color +
        f'{key}'.ljust(15, '.') +
        f' {value}'.rjust(0, '.') +
        nocolor
    )
    print(ret)
    return ret
