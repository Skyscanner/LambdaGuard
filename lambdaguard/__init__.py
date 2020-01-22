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
import boto3
from pathlib import Path
from shutil import rmtree
from lambdaguard.utils.arnparse import arnparse
from lambdaguard.utils.log import debug
from lambdaguard.utils.cli import parse_args, align, header, nocolor, green, orange
from lambdaguard.utils.log import configure_log
from lambdaguard.utils.paginator import paginate
from lambdaguard.core.Lambda import Lambda
from lambdaguard.core.STS import STS
from lambdaguard.visibility.Statistics import Statistics
from lambdaguard.visibility.Report import VisibilityReport
from lambdaguard.visibility.HTMLReport import HTMLReport
from lambdaguard.security.LambdaWrite import LambdaWrite
from lambdaguard.security.Report import SecurityReport


def get_functions(args):
    if args.function:
        yield args.function

    elif args.input:
        with Path(args.input).open() as f:
            for _ in f.read().split('\n'):
                yield _

    else:
        client = boto3.Session(
            profile_name=args.profile,
            aws_access_key_id=args.keys[0],
            aws_secret_access_key=args.keys[1],
            region_name=args.region
        ).client('lambda')
        for page in paginate(client, 'list_functions'):
            for function in page['Functions']:
                yield function['FunctionArn']


def run(arguments=''):
    args = parse_args(arguments)

    if args.html:
        HTMLReport(args.output).save()
        if args.verbose:
            print(f'HTML report saved to {args.output}/report.html')
        exit(0)

    rmtree(args.output, ignore_errors=True)
    Path(args.output).mkdir(parents=True, exist_ok=True)
    configure_log(args.output)
    identity = STS(f'arn:aws:sts:{args.region}', args.profile, args.keys[0], args.keys[1])

    if args.verbose:
        print(header, end='\n\n')
        for _ in ['UserId', 'Account', 'Arn']:
            align(_, identity.caller[_], orange)
        print('')

    statistics = Statistics(args.output)
    visibility = VisibilityReport(args.output)
    writes = LambdaWrite(args)

    for arn_str in get_functions(args):
        try:
            arn = arnparse(arn_str)
            if args.verbose:
                count = '[' + f'{statistics.statistics["lambdas"]+1}'.rjust(4, ' ') + '] '
                print(f'\r{green}{count}{arn.resource}{nocolor}'.ljust(100, ' '), end='')
            lmbd = Lambda(arn.full, args, identity)
            for w in writes.get_for_lambda(arn.full):
                lmbd.set_writes(w)
            statistics.parse(lmbd.report())
            visibility.save(lmbd.report())
        except Exception:
            debug(arn_str)

    SecurityReport(args.output).save()
    HTMLReport(args.output).save()

    if args.verbose:
        print('\r' + ' ' * 100, end='\r')  # clear
        align('Lambdas', statistics.statistics["lambdas"])
        align('Security', statistics.statistics["security"]["count"])
        align('Triggers', statistics.statistics["triggers"]["count"])
        align('Resources', statistics.statistics["resources"]["count"])
        align('Layers', statistics.statistics["layers"])
        align('Runtimes', len(statistics.statistics["runtimes"]["items"]))
        align('Regions', len(statistics.statistics["regions"]["items"]))
        print('')
        align('Report', f'{args.output}/report.html')
        align('Log', f'{args.output}/lambdaguard.log')
        print('\n')
