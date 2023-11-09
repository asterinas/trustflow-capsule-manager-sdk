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

import ctypes
import glob
import os
from enum import Enum, unique

from google.protobuf.json_format import MessageToJson, Parse
from sdc.error import CapsuleManagerError
from sdc.ual.constants import REPORT_BUFFER_SIZE
from secretflowapis.v2.sdc import ual_pb2

cur_dir = os.path.dirname(os.path.realpath(__file__))
lib_dir = os.path.join(cur_dir, "../lib")
lib_generation_path = glob.glob(os.path.join(lib_dir, "libgeneration*.so"))[0]
lib_verfication_path = glob.glob(os.path.join(lib_dir, "libverification*.so"))[0]
ual_generation = ctypes.cdll.LoadLibrary(lib_generation_path)
ual_verfication = ctypes.cdll.LoadLibrary(lib_verfication_path)


@unique
class ReportType(Enum):
    BACK_GROUND_CHECK = "BackgroundCheck"
    PASSPORT = "Passport"

    @staticmethod
    def from_str(label: str):
        if label == "BackgroundCheck":
            return ReportType.BACK_GROUND_CHECK
        elif label == "Passport":
            return ReportType.PASSPORT
        else:
            raise NotImplementedError


def create_report(
    type: ReportType, user_data: bytes
) -> ual_pb2.UnifiedAttestationReport:
    """API for unified attestation report generation

    Args:
        type: Type of report: `BackgroundCheck` or `Passport`
        user_data: limits in 32 Bytes

    Returns:
        str: report in json format
    """
    params = ual_pb2.UnifiedAttestationReportParams()
    params.hex_user_data = user_data
    params_str = MessageToJson(
        params, preserving_proto_field_name=True, including_default_value_fields=True
    )
    tee_identity = b"1"
    report_json_buf = ctypes.create_string_buffer(REPORT_BUFFER_SIZE)
    report_json_len = ctypes.c_int(REPORT_BUFFER_SIZE)
    err_code = ual_generation.UnifiedAttestationGenerateReport(
        tee_identity,
        type.encode("utf-8"),
        b"",
        params_str.encode("utf-8"),
        len(params_str),
        report_json_buf,
        ctypes.byref(report_json_len),
    )
    if err_code != 0:
        raise CapsuleManagerError(err_code, "generation failed.")

    report_json = report_json_buf.raw[: report_json_len.value].decode("utf-8")
    report = ual_pb2.UnifiedAttestationReport()
    Parse(report_json, report)

    return report


def verify_report(
    report: ual_pb2.UnifiedAttestationReport, policy: ual_pb2.UnifiedAttestationPolicy
):
    """API for unified attestation report verification

    Args:
        report (str): The serialized JSON string of UnifiedAttestationReport.
        policy (str): The serialized JSON string for UnifiedAttestationPolicy.

    """
    report_str = MessageToJson(
        report, preserving_proto_field_name=True, including_default_value_fields=True
    )
    policy_str = MessageToJson(policy, preserving_proto_field_name=True)

    err_code = ual_verfication.UnifiedAttestationVerifyReport(
        report_str.encode("utf-8"),
        len(report_str),
        policy_str.encode("utf-8"),
        len(policy_str),
    )
    if err_code != 0:
        raise CapsuleManagerError(err_code, "verify failed.")
