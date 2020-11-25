# <img src="lambdaguard/assets/logo.png" width="40px" style="vertical-align:middle" alt="LambdaGuard" style=""> LambdaGuard

[![](https://img.shields.io/pypi/v/LambdaGuard.svg)](https://pypi.python.org/pypi/LambdaGuard/)
[![](https://github.com/Skyscanner/LambdaGuard/workflows/build/badge.svg)](https://github.com/Skyscanner/LambdaGuard/actions)
[![](https://img.shields.io/github/issues/Skyscanner/LambdaGuard)](https://github.com/Skyscanner/LambdaGuard/issues)
[![](https://img.shields.io/github/issues-pr/Skyscanner/LambdaGuard)](https://github.com/Skyscanner/LambdaGuard/pulls)
[![](https://img.shields.io/pypi/dm/LambdaGuard)](https://img.shields.io/pypi/dm/LambdaGuard)

AWS Lambda is an event-driven, serverless computing platform provided by Amazon Web Services. It is a computing service that runs code in response to events and automatically manages the computing resources required by that code. 

LambdaGuard is an AWS Lambda auditing tool designed to create asset visibility and provide actionable results. It provides a meaningful overview in terms of statistical analysis, AWS service dependencies and configuration checks from the security perspective.

## Requirements
- Python 3.6+
- Java 11 (optional for SonarQube)

## Install

### From PyPI
```
pip3 install lambdaguard
```

### From Github
```
git clone https://github.com/Skyscanner/lambdaguard
cd lambdaguard
sudo make install
```

### AWS Access
You will need a set of AWS access keys and permissions to run LambdaGuard.
```
make aws
```
Create a profile in `~/.aws/credentials` with the newly created keys. 
```
[LambdaGuardProfile]
aws_access_key_id = ...
aws_secret_access_key = ...
```
Alternatively, you can use the keys directly as CLI arguments (not recommended).

## Run
- `lambdaguard --help`
- `lambdaguard --function arn:aws:lambda:function`
- `lambdaguard --input function-arns.txt`
- `lambdaguard --output /tmp/lambdaguard`
- `lambdaguard --profile LambdaGuardProfile`
- `lambdaguard --keys ACCESS_KEY_ID SECRET_ACCESS_KEY`
- `lambdaguard --region eu-west-1`
- `lambdaguard --verbose`

## SonarQube: Static Code Analysis

### Download sonar-scanner-cli
- https://github.com/SonarSource/sonar-scanner-cli

### Build SonarQube
- `make sonarqube`

### Use SonarQube
- `lambdaguard --sonarqube config.json`

Config should have the following format:

```json
{
    "command": "sonar-scanner -X",
    "url": "http://localhost:9000",
    "login": "admin",
    "password": "admin"
}
```

## Development
```
make -B clean
make dev
. dev/bin/activate
make install-dev
make test
```
