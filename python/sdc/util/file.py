# Copyright 2023 Ant Group Co., Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from typing import Any
import yaml


def read_file(file_path: str, mode: str):
    with open(file_path, mode) as f:
        res = f.read()
    return res


def read_yaml_file(file_path: str):
    with open(file_path) as f:
        res = yaml.safe_load(f)
    return res


def write_file(file_path: str, mode: str, content: Any):
    with open(file_path, mode) as f:
        f.write(content)
