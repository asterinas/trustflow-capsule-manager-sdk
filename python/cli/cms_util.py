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

import json
import click
import base64
from sdc.crypto import asymm
from sdc.util import crypto
from sdc.util import file
from sdc.util import tool
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


@click.group()
def cms_util():
    pass


@cms_util.command()
@click.option(
    "--private-key-file",
    type=click.STRING,
    help="file path for storing private key",
)
@click.option(
    "--cert-file",
    type=click.STRING,
    help="file path for storing cert chain which is list",
)
def generate_rsa_keypair(private_key_file, cert_file):
    """
    generate rsa key pair (private_key, cert_chain)
    """
    (
        pri_key_pem,
        cert_pems,
    ) = crypto.generate_rsa_keypair()
    if private_key_file:
        file.write_file(private_key_file, "w", pri_key_pem.decode("utf-8"))
    if cert_file:
        file.write_file(cert_file, "w", cert_pems[0].decode("utf-8"))


@cms_util.command()
@click.option(
    "--cert-file",
    type=click.STRING,
    multiple=True,
    required=True,
    help="a list of cert files, the order is important, the last file is CA cert",
)
def generate_party_id(cert_file):
    """
    generate the party id according to the certificate
    """
    cert_chain = []
    for cert in cert_file:
        cert_chain.append(file.read_file(cert, "r"))
    print(tool.generate_party_id_from_cert(cert_chain[-1].encode("utf-8")))


@cms_util.command()
@click.option(
    "--bit-len", type=click.INT, default=128, help="the bit len of secret key"
)
def generate_data_key_b64(bit_len):
    """
    generate the base64 encode data key
    """
    data_key = AESGCM.generate_key(bit_len)
    print(base64.b64encode(data_key).decode("utf-8"))


@cms_util.command()
@click.option(
    "--source-file",
    type=click.STRING,
    required=True,
    help="the source file which needs to be encrypted",
)
@click.option(
    "--dest-file",
    type=click.STRING,
    help="the dest file which stores encrypted data",
)
@click.option(
    "--data-key-b64",
    type=click.UNPROCESSED,
    required=True,
    help="the secret key used to encrypt data in base64 encode format",
)
def encrypt_file(source_file, dest_file, data_key_b64):
    """
    encrypt file using data key
    """
    data_key: bytes = base64.b64decode(data_key_b64)
    if dest_file is None or len(dest_file) == 0:
        dest_file = source_file + ".enc"
    crypto.encrypt_file(source_file, dest_file, data_key)


@cms_util.command()
@click.option(
    "--source-file",
    type=click.STRING,
    required=True,
    help="the source file which needs to be decrypted",
)
@click.option(
    "--dest-file",
    type=click.STRING,
    help="the dest file which stores decrypted data",
)
@click.option(
    "--data-key-b64",
    type=click.UNPROCESSED,
    required=True,
    help="the secret key used to decrypt data in base64 encode format",
)
def decrypt_file(source_file, dest_file, data_key_b64):
    """
    decrypt file using data key
    """
    data_key: bytes = base64.b64decode(data_key_b64)
    if dest_file is None or len(dest_file) == 0:
        dest_file = source_file + ".dec"
    crypto.decrypt_file(source_file, dest_file, data_key)


@cms_util.command()
@click.option(
    "--file",
    type=click.STRING,
    required=True,
    help="the file which needs to be encrypted",
)
@click.option(
    "--data-key-b64",
    type=click.UNPROCESSED,
    required=True,
    help="the secret key used to decrypt data in base64 encode format",
)
def encrypt_file_inplace(file, data_key_b64):
    """
    encrypt file inplace using data key, it will change origin file
    """
    data_key: bytes = base64.b64decode(data_key_b64)
    crypto.encrypt_file_inplace(file, data_key)


@cms_util.command()
@click.option(
    "--file",
    type=click.STRING,
    required=True,
    help="the file which needs to be decrypted",
)
@click.option(
    "--data-key-b64",
    type=click.UNPROCESSED,
    required=True,
    help="the secret key used to decrypt data in base64 encode format",
)
def decrypt_file_inplace(file, data_key_b64):
    """
    decrypt file inplace using data key, it will change origin file
    """
    data_key: bytes = base64.b64decode(data_key_b64)
    crypto.decrypt_file_inplace(file, data_key)


@cms_util.command()
@click.option(
    "--config-file", type=click.STRING, required=True, help="the config file for voting"
)
def generate_voter_sign(config_file):
    """
    generate voter signature when exporting the result data
    """
    config = file.read_yaml_file(config_file)
    # get private key
    private_key = file.read_file(config.pop("private_key_file"), "r").encode("utf-8")
    # get requester's sign
    request_sign = config.pop("vote_request_signature")

    body_str = json.dumps(config)
    body_b64 = base64.b64encode(body_str.encode("utf-8")).decode("utf-8")
    signature = base64.b64encode(
        asymm.RsaSigner(private_key, "RS256")
        .update(body_b64.encode("utf-8"))
        .update(request_sign.encode("utf-8"))
        .sign()
    ).decode("utf-8")
    print(signature)


@cms_util.command()
@click.option(
    "--config-file", type=click.STRING, required=True, help="the config file for voting"
)
@click.option(
    "--dest-file", type=click.STRING, help="the dest file to store voting result"
)
def generate_data_export_cert(config_file, dest_file):
    """
    generate the vote result when exporting the result data
    """
    config = file.read_yaml_file(config_file)
    # config["vote_request"]
    vote_request_config = dict()
    # cert_chain
    cert_pems_str = list()
    for filename in config["vote_request"].pop("cert_chain_file"):
        cert_pems_str.append(file.read_file(filename, "r"))
    vote_request_config["cert_chain"] = cert_pems_str

    # signature
    if config["vote_request"]["vote_request_signature"]:
        vote_request_signature = config["vote_request"]["vote_request_signature"]
    config["vote_request"].pop("vote_request_signature", None)

    # private-key
    if config["vote_request"]["private_key_file"]:
        private_key = file.read_file(
            config["vote_request"]["private_key_file"], "r"
        ).encode("utf-8")
    config["vote_request"].pop("private_key_file", None)

    # body
    vote_body_str = json.dumps(config["vote_request"])
    vote_request_config["body"] = base64.b64encode(
        vote_body_str.encode("utf-8")
    ).decode("utf-8")

    # vote_request_signature
    if private_key:
        vote_request_config["vote_request_signature"] = base64.b64encode(
            asymm.RsaSigner(private_key, "RS256")
            .update(vote_request_config["body"].encode("utf-8"))
            .sign()
        ).decode("utf-8")
    else:
        vote_request_config["vote_request_signature"] = vote_request_signature

    # config["vote_invite"]
    invite_list_config = list()
    if "vote_invite" in config and config["vote_invite"]:
        for invite in config["vote_invite"]:
            invite_config = dict()
            # cert_chain
            cert_pems_str = list()
            for filename in invite.pop("cert_chain_file"):
                cert_pems_str.append(file.read_file(filename, "r"))
            invite_config["cert_chain"] = cert_pems_str

            # signature
            voter_signature = invite.pop("voter_signature", None)

            # private key
            invite_private_key = invite.pop("private_key_file", None)
            if invite_private_key:
                invite_private_key = file.read_file(invite_private_key, "r").encode(
                    "utf-8"
                )

            # body
            invite_body_str = json.dumps(invite)
            invite_config["body"] = base64.b64encode(
                invite_body_str.encode("utf-8")
            ).decode("utf-8")

            if invite_private_key:
                invite_config["voter_signature"] = base64.b64encode(
                    asymm.RsaSigner(invite_private_key, "RS256")
                    .update(invite_config["body"].encode("utf-8"))
                    .update(
                        vote_request_config["vote_request_signature"].encode("utf-8")
                    )
                    .sign()
                ).decode("utf-8")
            else:
                invite_config["voter_signature"] = voter_signature

            invite_list_config.append(invite_config)

    # compose
    cfg = dict()
    cfg["vote_request"] = vote_request_config
    cfg["vote_invite"] = invite_list_config

    if dest_file:
        file.write_file(dest_file, "w", json.dumps(cfg))
    else:
        print(json.dumps(cfg))


if __name__ == "__main__":
    cms_util()
