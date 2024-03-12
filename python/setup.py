#
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
#
import os
import shutil
from pathlib import Path

import setuptools
from setuptools.command import build_ext


def read(fname):
    with open(os.path.join(os.path.dirname(__file__), fname)) as f:
        return f.read()


# [ref](https://github.com/google/trimmed_match/blob/master/setup.py)
class BazelExtension(setuptools.Extension):
    """A C/C++ extension that is defined as a Bazel BUILD target."""

    def __init__(self, bazel_workspace, bazel_target, ext_name):
        self._bazel_target = bazel_target
        self._bazel_workspace = bazel_workspace
        setuptools.Extension.__init__(self, ext_name, sources=[])


class BuildBazelExtension(build_ext.build_ext):
    """A command that runs Bazel to build a C/C++ extension."""

    def run(self):
        for ext in self.extensions:
            self.bazel_build(ext)
        build_ext.build_ext.run(self)

    def bazel_build(self, ext):
        Path(self.build_temp).mkdir(parents=True, exist_ok=True)
        bazel_argv = [
            "bazel",
            "build",
            f"@{ext._bazel_workspace}//:{ext._bazel_target}",
            "--symlink_prefix="
            + os.path.join(os.path.abspath(self.build_temp), "bazel-"),
            "--compilation_mode=" + ("dbg" if self.debug else "opt"),
        ]

        self.spawn(bazel_argv)

        ext_bazel_bin_path = os.path.join(
            self.build_temp,
            "bazel-bin/external",
            ext._bazel_workspace,
            ext._bazel_target,
        )
        ext_dest_path = self.get_ext_fullpath(ext.name)
        Path(ext_dest_path).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ext_bazel_bin_path, ext_dest_path)


setuptools.setup(
    name="capsule-manager-sdk",
    version="0.1.3b",
    author="secretflow",
    author_email="secretflow-contact@service.alipay.com",
    description="Secure Data Capsule SDK for python",
    long_description_content_type="text/markdown",
    long_description="Secure Data Capsule SDK for python",
    license="Apache 2.0",
    url="https://github.com/secretflow/capsule-manager-sdk.git",
    packages=setuptools.find_namespace_packages(exclude=("tests", "tests.*")),
    install_requires=read("requirements.txt"),
    ext_modules=[
        BazelExtension(
            "jinzhao_attest", "libverification.so", "sdc/lib/libverification"
        ),
        BazelExtension("jinzhao_attest", "libgeneration.so", "sdc/lib/libgeneration"),
    ],
    entry_points="""
        [console_scripts]
        cms=cli.cms:cms
        cms_util=cli.cms_util:cms_util
        cms_config=cli.cms_config:cms_config
    """,
    cmdclass=dict(build_ext=BuildBazelExtension),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: POSIX :: Linux",
    ],
    include_package_data=True,
)
