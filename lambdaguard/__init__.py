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
from pathlib import Path
from shutil import rmtree

import boto3

from lambdaguard.core.Lambda import Lambda
from lambdaguard.core.STS import STS
from lambdaguard.security.LambdaWrite import LambdaWrite
from lambdaguard.security.Report import SecurityReport
from lambdaguard.utils.arnparse import arnparse
from lambdaguard.utils.cli import align, green, header, nocolor, orange, parse_args
from lambdaguard.utils.log import configure_log, debug
from lambdaguard.utils.paginator import paginate
from lambdaguard.visibility.HTMLReport import HTMLReport
from lambdaguard.visibility.Report import VisibilityReport
from lambdaguard.visibility.Statistics import Statistics


def verbose(args, message, end=""):
    """
    Prints formatted message if verbose mode is set
    """
    if args.verbose:
        print(f"\r{green}{message}{nocolor}".ljust(100, " "), end=end)


def get_client(args):
    """
    Returns a Lambda botocore client
    """
    return boto3.Session(
        profile_name=args.profile,
        aws_access_key_id=args.keys[0],
        aws_secret_access_key=args.keys[1],
        region_name=args.region,
    ).client("lambda")


def get_regions(args):
    """
    Valid region specification:
        Single:     eu-west-1
        Multiple:   eu-west-1,ap-south-1,us-east-2
        All:        all
    Returns regions as a Python list
    """
    if not isinstance(args.region, str):
        raise ValueError("No region specified")
    if args.function:
        return [arnparse(args.function).region]
    available = boto3.Session().get_available_regions("lambda")
    if args.region == "all":
        return available
    regions = args.region.split(",")
    if not regions:
        raise ValueError("No region specified")
    for region in regions:
        if region not in available:
            raise ValueError(f'Invalid region "{region}"')
    return regions


def get_usage(args):
    """
    Returns Python dict with number of Lambdas per region
    """
    usage = {}
    for region in get_regions(args):
        args.region = region
        verbose(args, f"Loading regions ({region})")
        try:
            client = get_client(args)
            settings = client.get_account_settings()
            function_count = settings["AccountUsage"]["FunctionCount"]
            if function_count:
                usage[region] = function_count
        except Exception:
            debug(region)
    return usage


def get_functions(args):
    """
    Generator for listing Lambda functions
    Yields Lambda function ARNs
    """
    if args.function:
        yield args.function
    elif args.input:
        with Path(args.input).open() as f:
            for _ in f.read().split("\n"):
                yield _
    else:
        client = get_client(args)
        for page in paginate(client, "list_functions"):
            for function in page["Functions"]:
                yield function["FunctionArn"]


def run(arguments=""):
    """
    Main routine
    """
    args = parse_args(arguments)

    verbose(args, header, end="\n\n")

    if args.html:
        HTMLReport(args.output).save()
        verbose(args, f"Generated {args.output}/report.html", end="\n\n")
        exit(0)

    rmtree(args.output, ignore_errors=True)
    Path(args.output).mkdir(parents=True, exist_ok=True)
    configure_log(args.output)
    usage = get_usage(args)
    verbose(args, "Loading identity")
    region = list(usage.keys())[0]
    sts_arn = f"arn:aws:sts:{region}"
    identity = STS(sts_arn, args.profile, args.keys[0], args.keys[1])
    if args.verbose:
        for _ in ["UserId", "Account", "Arn"]:
            align(_, identity.caller[_], orange)
        print("")

    statistics = Statistics(args.output)
    visibility = VisibilityReport(args.output)
    writes = LambdaWrite(args)
    total_count = 0
    for region_count in usage.values():
        total_count += region_count

    for region in usage.keys():
        args.region = region
        for arn_str in get_functions(args):
            try:
                arn = arnparse(arn_str)
                counter = f'[ {statistics.statistics["lambdas"]+1}/{total_count} ] '
                verbose(args, f"{counter}{arn.resource}")
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
        print("\r" + " " * 100, end="\r")  # clear
        align("Lambdas", statistics.statistics["lambdas"])
        align("Security", statistics.statistics["security"]["count"])
        align("Triggers", statistics.statistics["triggers"]["count"])
        align("Resources", statistics.statistics["resources"]["count"])
        align("Layers", statistics.statistics["layers"])
        align("Runtimes", len(statistics.statistics["runtimes"]["items"]))
        align("Regions", len(statistics.statistics["regions"]["items"]))
        print("")
        align("Report", f"{args.output}/report.html")
        align("Log", f"{args.output}/lambdaguard.log")
        print("")
