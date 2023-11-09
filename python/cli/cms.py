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

import os
from typing import List
import click
import base64
from sdc.util import file
from sdc import capsule_manager_frame
from google.protobuf import json_format

current_work_dir = os.path.dirname(__file__)
CONFIG_FILE = current_work_dir + "/cms/cli.yaml"


def read_rsa_keypair(cfg) -> tuple:
    if (
        "cert_pems_file" in cfg
        and "private_key_file" in cfg
        and cfg["private_key_file"] is not None
        and cfg["cert_pems_file"] is not None
    ):
        cert_pems_str = list()
        for filename in cfg["cert_pems_file"]:
            cert_pems_str.append(file.read_file(filename, "r"))
        private_key_str = file.read_file(cfg["private_key_file"], "r")
        if isinstance(cert_pems_str, List):
            return (
                [cert.encode("utf-8") for cert in cert_pems_str],
                private_key_str.encode("utf-8"),
            )
    return None, None


@click.group()
@click.option(
    "--config-file", type=click.STRING, default=CONFIG_FILE, help="the config path"
)
@click.pass_context
def cms(ctx, config_file):
    global CONFIG_FILE
    CONFIG_FILE = config_file
    config = file.read_yaml_file(CONFIG_FILE)

    if (
        config["root_ca_file"] is not None
        and config["private_key_file"] is not None
        and config["cert_chain_file"] is not None
    ):
        root_ca: bytes = file.read_file(config["root_ca_file"], "r").encode("utf-8")
        private_key: bytes = file.read_file(config["private_key_file"], "r").encode(
            "utf-8"
        )
        cert_chain: bytes = file.read_file(config["cert_chain_file"], "r").encode(
            "utf-8"
        )

        ctx.obj = capsule_manager_frame.CapsuleManagerFrame(
            config["host"],
            config["mr_enclave"],
            capsule_manager_frame.CredentialsConf(root_ca, private_key, cert_chain),
            config["sim"],
        )
    else:
        ctx.obj = capsule_manager_frame.CapsuleManagerFrame(
            config["host"], config["mr_enclave"], None, config["sim"]
        )


@cms.command()
@click.pass_context
def get_public_key(ctx):
    """
    get the pem format of public key of CapsuleManager
    """
    public_key_pem = ctx.obj.get_public_key()
    print(public_key_pem)


@cms.command()
@click.pass_context
def register_cert(ctx):
    """
    upload the cert of party using the sdk to CapsuleManager
    """
    config = file.read_yaml_file(CONFIG_FILE)
    config = config["common"]
    cert_pems, private_key = read_rsa_keypair(config)

    ctx.obj.register_cert(config["party_id"], cert_pems, config["scheme"], private_key)


@cms.command()
@click.pass_context
def get_data_keys(ctx):
    """
    get data_keys of several resource_uris from CapsuleManager
    """
    config = file.read_yaml_file(CONFIG_FILE)
    common = config["common"]
    ownered = config["get_data_keys"]
    cert_pems, private_key = read_rsa_keypair(common)

    result = ctx.obj.get_data_keys(
        ownered["initiator_party_id"],
        ownered["scope"],
        ownered["op_name"],
        ownered["resource_uris"],
        ownered["env"],
        ownered["global_attrs"],
        ownered["columns"],
        ownered["attrs"],
        cert_pems,
        private_key,
    )
    result = [
        (resource_uri, data_key, base64.b64encode(data_key).decode("utf-8"))
        for (resource_uri, data_key) in result
    ]
    print(result)


@cms.command()
@click.pass_context
def register_data_keys(ctx):
    """
    upload data_keys of several resource_uris to CapsuleManager
    """
    config = file.read_yaml_file(CONFIG_FILE)
    common = config["common"]
    ownered = config["register_data_keys"]
    cert_pems, private_key = read_rsa_keypair(common)

    data_keys = [base64.b64decode(data_key) for data_key in ownered["data_key_b64s"]]
    ctx.obj.create_data_keys(
        common["party_id"],
        ownered["resource_uris"],
        data_keys,
        cert_pems,
        private_key,
    )


@cms.command()
@click.pass_context
def get_data_policys(ctx):
    """
    get data policy of the party using sdk from CapsuleManager
    """
    config = file.read_yaml_file(CONFIG_FILE)
    common = config["common"]
    ownered = config["get_data_policys"]
    cert_pems, private_key = read_rsa_keypair(common)

    result = ctx.obj.get_data_policys(
        common["party_id"], ownered["scope"], cert_pems, private_key
    )
    for policy in result:
        print(json_format.MessageToJson(policy))


@cms.command()
@click.pass_context
def register_data_policy(ctx):
    """
    upload data policy of a specific data to CapsuleManager
    """
    config = file.read_yaml_file(CONFIG_FILE)
    common = config["common"]
    ownered = config["register_data_policy"]
    cert_pems, private_key = read_rsa_keypair(common)

    ctx.obj.create_data_policy(
        common["party_id"],
        ownered["scope"],
        ownered["data_uuid"],
        ownered["rule_ids"],
        ownered["grantee_party_ids"],
        ownered["columns"],
        ownered["global_constraints"],
        ownered["op_constraints_name"],
        ownered["op_constraints_body"],
        cert_pems,
        private_key,
    )


@cms.command()
@click.pass_context
def delete_data_policy(ctx):
    """
    delete data policy of a specific data to CapsuleManager
    """
    config = file.read_yaml_file(CONFIG_FILE)
    common = config["common"]
    ownered = config["delete_data_policy"]
    cert_pems, private_key = read_rsa_keypair(common)

    ctx.obj.delete_data_policy(
        common["party_id"],
        ownered["scope"],
        ownered["data_uuid"],
        cert_pems,
        private_key,
    )


@cms.command()
@click.pass_context
def add_data_rule(ctx):
    """
    add data rule for a specific policy to CapsuleManager
    """
    config = file.read_yaml_file(CONFIG_FILE)
    common = config["common"]
    ownered = config["add_data_rule"]
    cert_pems, private_key = read_rsa_keypair(common)

    ctx.obj.add_data_rule(
        common["party_id"],
        ownered["scope"],
        ownered["data_uuid"],
        ownered["rule_id"],
        ownered["grantee_party_ids"],
        ownered["columns"],
        ownered["global_constraints"],
        ownered["op_constraints_name"],
        ownered["op_constraints_body"],
        cert_pems,
        private_key,
    )


@cms.command()
@click.pass_context
def delete_data_rule(ctx):
    """
    delete data rule for a specific policy to CapsuleManager
    """
    config = file.read_yaml_file(CONFIG_FILE)
    common = config["common"]
    ownered = config["delete_data_rule"]
    cert_pems, private_key = read_rsa_keypair(common)

    ctx.obj.delete_data_rule(
        common["party_id"],
        ownered["scope"],
        ownered["data_uuid"],
        ownered["rule_id"],
        cert_pems,
        private_key,
    )


@cms.command()
@click.pass_context
def get_export_data_key(ctx):
    """
    get the data key of export data(often is generated from origin
    datas of multiply differernt partys) from CapsuleManager
    """
    config = file.read_yaml_file(CONFIG_FILE)
    common = config["common"]
    ownered = config["get_export_data_key"]
    cert_pems, private_key = read_rsa_keypair(common)

    data_key = ctx.obj.get_export_data_key(
        common["party_id"],
        ownered["resource_uri"],
        file.read_file(ownered["data_export_certificate_file"], "r"),
        cert_pems,
        private_key,
    )
    print(data_key, base64.b64encode(data_key))


@cms.command()
@click.pass_context
def delete_data_key(ctx):
    """
    delete the data key of a specific resource_uri from CapsuleManager
    """
    config = file.read_yaml_file(CONFIG_FILE)
    common = config["common"]
    ownered = config["delete_data_key"]
    cert_pems, private_key = read_rsa_keypair(common)

    ctx.obj.delete_data_key(
        common["party_id"],
        ownered["resource_uri"],
        cert_pems,
        private_key,
    )


if __name__ == "__main__":
    cms()
