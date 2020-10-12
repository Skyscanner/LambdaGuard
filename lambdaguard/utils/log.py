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
import logging
import logging.config
import traceback
from pathlib import Path


def configure_log(path=""):
    logpath = Path(path, "lambdaguard.log").as_posix()
    logging.config.dictConfig(
        {
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {
                "default": {
                    "class": "logging.Formatter",
                    "style": "{",
                    "datefmt": "%Y-%m-%d %H:%M",
                    "format": "[{asctime:s}] {message:s}\n",
                }
            },
            "handlers": {
                "lambdaguard-log": {
                    "level": "DEBUG",
                    "class": "logging.handlers.WatchedFileHandler",
                    "formatter": "default",
                    "filename": logpath,
                    "mode": "w",
                    "encoding": "utf-8",
                }
            },
            "loggers": {},
            "root": {"handlers": ["lambdaguard-log"], "level": "WARNING"},
        }
    )


def debug(arn=""):
    # Get exception name and description
    trace = traceback.format_exc().strip()
    etype, evalue = trace.split("\n")[-1].split(": ", 1)

    # Drop known messages
    if "botocore.e" in trace:
        # Differently formatted exception messages
        if not etype.startswith("botocore"):
            etype, evalue = trace.split("\n")[-2].split(": ", 1)

        if etype == "botocore.errorfactory.NoSuchEntityException":
            return None  # Missing policy
        elif etype == "botocore.errorfactory.ResourceNotFoundException":
            return None  # Missing resource
        elif etype == "botocore.exceptions.ParamValidationError":
            return None  # Invalid resource name
        elif etype == "botocore.errorfactory.NoSuchBucket":
            return None  # Missing S3 bucket
        elif etype == "botocore.errorfactory.NotFoundException":
            return None  # Missing SNS topic
        elif etype == "botocore.errorfactory.QueueDoesNotExist":
            return None  # Missing SQS queue
        elif etype == "botocore.exceptions.ClientError":
            if "AccessDenied" in evalue:
                # TODO: track denied resources
                return None
            elif "NoSuchBucketPolicy" in evalue:
                return None  # Missing S3 bucket policy
            elif "ServerSideEncryptionConfigurationNotFoundError" in evalue:
                return None  # Missing S3 bucket encryption
            elif "ValidationException" in evalue:
                return None  # Invalid resource value
            elif "arn:aws:lambda:::awslayer:" in evalue:
                return None  # Update opt-in/out
    elif trace.startswith("NoneType: None"):
        return None  # Empty
    elif etype == "ValueError":
        if evalue.startswith("Invalid endpoint:"):
            return None  # Invalid resource configuration

    # Log
    logging.warning(f"[{arn}]\n{trace}")
    return trace
