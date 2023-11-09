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
import click
import stat
import yaml

current_work_dir = os.path.dirname(__file__)
CONFIG_FILE = current_work_dir + "/cms/cli.yaml"


def restore_config(cfg: dict):
    with open(CONFIG_FILE + ".bak", "w") as f:
        yaml.dump(cfg, f)
    os.remove(CONFIG_FILE)
    os.rename(CONFIG_FILE + ".bak", CONFIG_FILE)
    os.chmod(CONFIG_FILE, stat.S_IRWXU + stat.S_IRWXG + stat.S_IRWXO)


def set_dict_value(cfg: dict, key, value):
    if value is not None:
        cfg[key] = value


@click.group()
@click.pass_context
@click.option(
    "--config-file", type=click.STRING, default=CONFIG_FILE, help="config file path"
)
def cms_config(ctx, config_file):
    global CONFIG_FILE
    CONFIG_FILE = config_file
    with open(CONFIG_FILE) as f:
        config = yaml.safe_load(f)
    ctx.obj = config


@cms_config.command()
@click.option("--host", type=click.STRING, help="the host of capsule manager")
@click.option(
    "--mr-enclave", type=click.STRING, help="the mrenclave of capsule manager"
)
@click.option("--sim", type=click.BOOL, help="the mode of capsule manager")
@click.option(
    "--root-ca-file", type=click.STRING, help="the root CA of capsule manager"
)
@click.option(
    "--private-key-file",
    type=click.STRING,
    help="the private key of the party using capsule manager sdk",
)
@click.option(
    "--cert-chain-file",
    type=click.STRING,
    multiple=True,
    help="the cert chain of the party using capsule manager sdk",
)
@click.pass_context
def init(ctx, host, mr_enclave, sim, root_ca_file, private_key_file, cert_chain_file):
    set_dict_value(ctx.obj, "host", host)
    set_dict_value(ctx.obj, "mr_enclave", mr_enclave)
    set_dict_value(ctx.obj, "sim", sim)
    set_dict_value(ctx.obj, "root_ca_file", root_ca_file)
    set_dict_value(ctx.obj, "private_key_file", private_key_file)
    set_dict_value(ctx.obj, "cert_chain_file", cert_chain_file)

    restore_config(ctx.obj)


@cms_config.command()
@click.option(
    "--party-id", type=click.STRING, help="the party using capsule manager sdk"
)
@click.option(
    "--cert-pems-file",
    type=click.STRING,
    multiple=True,
    help="the cert chain id of the party using capsule manager sdk",
)
@click.option("--scheme", type=click.STRING, help="the scheme of key, RSA or SM2")
@click.option(
    "--private-key-file",
    type=click.STRING,
    help="the private key of the party using capsule manager sdk",
)
@click.pass_context
def common(ctx, party_id, cert_pems_file, scheme, private_key_file):
    if "common" not in ctx.obj:
        ctx.obj["common"] = {}

    set_dict_value(ctx.obj["common"], "party_id", party_id)
    set_dict_value(ctx.obj["common"], "cert_pems_file", cert_pems_file)
    set_dict_value(ctx.obj["common"], "scheme", value=scheme)
    set_dict_value(ctx.obj["common"], "private_key_file", private_key_file)

    restore_config(ctx.obj)


@cms_config.command()
@click.option(
    "--initiator-party-id",
    type=click.STRING,
    help="Identity of task initiator",
)
@click.option(
    "--scope",
    type=click.STRING,
    default="default",
    help="corresponding to the scope in the policy, only policies that are the same as the scope take effect",
)
@click.option(
    "--op_name", type=click.STRING, help="behavior of operating on this resource"
)
@click.option(
    "--env",
    type=click.STRING,
    help="in what environment is the data used (Json format)",
)
@click.option(
    "--global-attrs",
    type=click.STRING,
    help="application-specific and data-independent attibutes (Json format)",
)
@click.pass_context
def get_data_keys(ctx, initiator_party_id, scope, op_name, env, global_attrs):
    if "get_data_keys" not in ctx.obj:
        ctx.obj["get_data_keys"] = {}

    set_dict_value(ctx.obj["get_data_keys"], "initiator_party_id", initiator_party_id)
    set_dict_value(ctx.obj["get_data_keys"], "scope", scope)
    set_dict_value(ctx.obj["get_data_keys"], "op_name", op_name)
    set_dict_value(ctx.obj["get_data_keys"], "env", env)
    set_dict_value(ctx.obj["get_data_keys"], "global_attrs", global_attrs)

    restore_config(ctx.obj)


@cms_config.command()
@click.option(
    "--scope",
    type=click.STRING,
    default="default",
    help="corresponding to the scope in the policy",
)
@click.pass_context
def get_data_policys(ctx, scope):
    if "get_data_policys" not in ctx.obj:
        ctx.obj["get_data_policys"] = {}

    set_dict_value(ctx.obj["get_data_policys"], "scope", scope)

    restore_config(ctx.obj)


@cms_config.command()
@click.option(
    "--scope",
    type=click.STRING,
    default="default",
    help="corresponding to the scope in the policy,",
)
@click.option("--data-uuid", type=click.STRING, help="the identifier of data")
@click.pass_context
def create_data_policy(ctx, scope, data_uuid):
    if "create_data_policy" not in ctx.obj:
        ctx.obj["create_data_policy"] = {}

    set_dict_value(ctx.obj["create_data_policy"], "scope", scope)
    set_dict_value(ctx.obj["create_data_policy"], "data_uuid", data_uuid)

    restore_config(ctx.obj)


@cms_config.command()
@click.option(
    "--scope",
    type=click.STRING,
    default="default",
    help="corresponding to the scope in the policy,",
)
@click.option("--data-uuid", type=click.STRING, help="the identifier of data")
@click.pass_context
def delete_data_policy(ctx, scope, data_uuid):
    if "delete_data_policy" not in ctx.obj:
        ctx.obj["delete_data_policy"] = {}

    set_dict_value(ctx.obj["delete_data_policy"], "scope", scope)
    set_dict_value(ctx.obj["delete_data_policy"], "data_uuid", data_uuid)

    restore_config(ctx.obj)


@cms_config.command()
@click.option(
    "--scope",
    type=click.STRING,
    default="default",
    help="corresponding to the scope in the policy,",
)
@click.option("--data-uuid", type=click.STRING, help="the identifier of data")
@click.option("--rule-id", type=click.STRING, help="the identifier of rule")
@click.pass_context
def add_data_rule(ctx, scope, data_uuid, rule_id):
    if "add_data_rule" not in ctx.obj:
        ctx.obj["add_data_rule"] = {}

    set_dict_value(ctx.obj["add_data_rule"], "scope", scope)
    set_dict_value(ctx.obj["add_data_rule"], "data_uuid", data_uuid)
    set_dict_value(ctx.obj["add_data_rule"], "rule_id", rule_id)

    restore_config(ctx.obj)


@cms_config.command()
@click.option(
    "--scope",
    type=click.STRING,
    default="default",
    help="corresponding to the scope in the policy",
)
@click.option("--data-uuid", type=click.STRING, help="the identifier of data")
@click.option("--rule-id", type=click.STRING, help="the identifier of rule")
@click.pass_context
def delete_data_rule(ctx, scope, data_uuid, rule_id):
    if "delete_data_rule" not in ctx.obj:
        ctx.obj["delete_data_rule"] = {}

    set_dict_value(ctx.obj["delete_data_rule"], "scope", scope)
    set_dict_value(ctx.obj["delete_data_rule"], "data_uuid", data_uuid)
    set_dict_value(ctx.obj["delete_data_rule"], "rule_id", rule_id)

    restore_config(ctx.obj)


if __name__ == "__main__":
    cms_config()
