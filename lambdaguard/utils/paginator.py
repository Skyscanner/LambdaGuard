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


def paginate(client, paginator, **kwargs):
    """
    Returns pages for given AWS paginator client and type.
    Example: iam client and "list_policies" paginator
    """
    marker = None
    while True:
        pages = client.get_paginator(paginator).paginate(
            **kwargs,
            PaginationConfig={
                'MaxItems': 10,
                'PageSize': 10,
                'StartingToken': marker
            }
        )
        for page in pages:
            yield page
        if 'NextMarker' not in page:
            break
        marker = page['NextMarker']
