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


def iterate(str_or_list):
    """
    Check is the given value is a string or list
    Returns values one by one as if it were a list
    """
    if type(str_or_list) == str:
        if not len(str_or_list.strip()):
            return StopIteration
        yield str_or_list
    elif type(str_or_list) == list:
        for _ in str_or_list:
            yield _
    else:
        raise TypeError(f'"{str_or_list}" is not a string or list')
