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

import base64
import grpc

from dataclasses import dataclass
from typing import List, Union
from google.protobuf import json_format
from google.protobuf import message
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography import x509
from sdc.crypto import asymm, symm
from sdc.error import CapsuleManagerError
from sdc.util import crypto, tool
from sdc.ual.constants import NONCE_SIZE_IN_SIZE
from secretflowapis.v2.sdc import ual_pb2
from secretflowapis.v2.sdc import jwt_pb2
from secretflowapis.v2.sdc.capsule_manager import (
    capsule_manager_pb2,
    capsule_manager_pb2_grpc,
)


@dataclass
class CredentialsConf:
    root_ca: bytes
    private_key: bytes
    cert_chain: bytes


class CapsuleManagerFrame(object):
    def __init__(self, host: str, mr_enclave: str, conf: CredentialsConf, sim=False):
        """CapsuleManager client

        Args:
            host: CapsuleManager endpoint
            mr_enclave: CapsuleManager mr_enclave
            sim (bool, optional): is in simulation mode. Defaults to False.
        """
        self.sim = sim
        if conf is None:
            channel = grpc.insecure_channel(host)
        else:
            credentials = grpc.ssl_channel_credentials(
                root_certificates=conf.root_ca,
                private_key=conf.private_key,
                certificate_chain=conf.cert_chain,
            )
            channel = grpc.secure_channel(host, credentials)

        self.stub = capsule_manager_pb2_grpc.CapsuleManagerStub(channel)
        self.mr_enclave = mr_enclave if mr_enclave is not None else ""

    @staticmethod
    def create_encrypted_request(
        request: message.Message,
        public_key: bytes,
        private_key: Union[bytes, str, rsa.RSAPrivateKey],
        cert_pems: List[bytes] = None,
    ) -> capsule_manager_pb2.EncryptedRequest:
        """encrypt request

        Args:
            request: the item will be encrypted
            public_key: the public key of capsule manager, it will be used to encrypt data key
            cert_pems: the cert chain of party, it will be used to verify signature and encrypt
            private_key: the private key of party, it will be used to sign and decrypt
        """
        jws = jwt_pb2.Jws()
        jws_JoseHeader = jws.JoseHeader()
        jws_JoseHeader.alg = "RS256"
        if cert_pems is not None:
            cert_chain = [
                # has padding
                base64.standard_b64encode(crypto.convert_pem_to_der(cert_pem)).decode(
                    "utf-8"
                )
                for cert_pem in cert_pems
            ]
            jws_JoseHeader.x5c.extend(cert_chain)
        jws.protected_header = tool.encode_base64(
            json_format.MessageToJson(jws_JoseHeader).encode("utf-8")
        )
        jws.payload = tool.encode_base64(
            json_format.MessageToJson(request).encode("utf-8")
        )

        jws.signature = tool.encode_base64(
            asymm.RsaSigner(private_key, "RS256")
            .update(jws.protected_header.encode("utf-8"))
            .update(b".")
            .update(jws.payload.encode("utf-8"))
            .sign()
        )

        jwe = jwt_pb2.Jwe()
        jwe_header = jwe.JoseHeader()
        jwe_header.alg = "RSA-OAEP-256"
        jwe_header.enc = "A128GCM"
        jwe.protected_header = tool.encode_base64(
            json_format.MessageToJson(jwe_header).encode("utf-8")
        )

        # generate temp data_key, it will be used to encrypt data
        data_key = AESGCM.generate_key(bit_length=128)
        # use public key of capsule manager to encrypt data key
        jwe.encrypted_key = tool.encode_base64(
            asymm.RsaEncryptor(public_key, "RSA-OAEP-256").encrypt(data_key)
        )

        nonce = crypto.gen_key(NONCE_SIZE_IN_SIZE)
        jwe.iv = tool.encode_base64(nonce)
        jwe.aad = ""

        (ciphertext, tag) = symm.AesGcmEncryptor(data_key, "A128GCM").encrypt(
            json_format.MessageToJson(jws).encode("utf-8"), nonce, b""
        )
        jwe.ciphertext = tool.encode_base64(ciphertext)
        jwe.tag = tool.encode_base64(tag)

        encrypted_request = capsule_manager_pb2.EncryptedRequest()
        encrypted_request.message.CopyFrom(jwe)
        encrypted_request.has_signature = True
        return encrypted_request

    @staticmethod
    def parse_from_encrypted_response(
        response: capsule_manager_pb2.EncryptedResponse,
        private_key: Union[bytes, str, rsa.RSAPrivateKey],
        msg: message.Message,
    ):
        """decrypt request

        Args:
            response: the item will be decrypted
            private_key: the private key of party, it will be used to decrypt
        """

        jwe = response.message
        jwe_header = jwe.JoseHeader()
        json_format.Parse(tool.decode_base64(jwe.protected_header), jwe_header)
        iv = tool.decode_base64(jwe.iv)
        ciphertext = tool.decode_base64(jwe.ciphertext)
        tag = tool.decode_base64(jwe.tag)
        add = tool.decode_base64(jwe.aad)

        data_key = asymm.RsaDecryptor(private_key, jwe_header.alg).decrypt(
            tool.decode_base64(jwe.encrypted_key)
        )
        plain_text = symm.AesGcmDecryptor(data_key, jwe_header.enc).decrypt(
            ciphertext, iv, add, tag
        )
        json_format.Parse(plain_text, msg)

    def get_public_key(self) -> bytes:
        """Get CapsuleManager public key"""
        request = capsule_manager_pb2.GetRaCertRequest()
        nonce_bytes = crypto.gen_key(32)
        request.nonce = tool.to_upper_hex(nonce_bytes)
        response = self.stub.GetRaCert(request)
        if response.status.code != 0:
            raise CapsuleManagerError(response.status.code, response.status.message)
        assert len(response.cert) != 0, "The CapsuleManager should have public key."

        if not self.sim:
            from sdc.ual import ual
            
            policy = ual_pb2.UnifiedAttestationPolicy()
            rule = policy.main_attributes.add()
            rule.str_tee_platform = "SGX_DCAP"
            rule.hex_ta_measurement = self.mr_enclave
            rule.bool_debug_disabled = "1"

            user_data = crypto.sha256(
                response.cert.encode("utf-8"), request.nonce.encode("utf-8")
            )
            rule.hex_user_data = tool.to_upper_hex(user_data)
            ual.verify_report(response.attestation_report, policy)

        cert = x509.load_pem_x509_certificate(response.cert.encode("utf-8"))
        return cert.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def register_cert(
        self,
        owner_party_id: str,
        cert_pems: List[bytes],
        scheme: str,
        private_key: Union[bytes, str, rsa.RSAPrivateKey],
    ):
        """register cert

        Args:
            owner_party_id: data owner
            cert_pems: cert chain. cert_pems[0] is  current cert
            scheme: `RSA`, `SM2`
            private_key: private key of party

        """
        request = capsule_manager_pb2.RegisterCertRequest()
        request.owner_party_id = owner_party_id
        request.certs.extend([cert_pem.decode("utf-8") for cert_pem in cert_pems])
        request.scheme = scheme

        encrypted_response = self.stub.RegisterCert(
            self.create_encrypted_request(
                request, self.get_public_key(), private_key, None
            )
        )
        if encrypted_response.status.code != 0:
            raise CapsuleManagerError(
                encrypted_response.status.code, encrypted_response.status.message
            )

    def get_data_keys(
        self,
        initiator_party_id: str,
        scope: str,
        op_name: str,
        resource_uris: List[str],
        env: str = None,
        global_attrs: str = None,
        columns: List[List[str]] = None,
        attrs: List[str] = None,
        cert_pems: List[bytes] = None,
        private_key: Union[bytes, str, rsa.RSAPrivateKey] = None,
    ) -> List[tuple]:
        """Get data keys

        Args:
            initiator_party_id: Identity of task initiator
            scope: Corresponding to the `scope` in the `Policy`,
                only policies that are the same as the scope take effect
            op_name: Behavior of operating on this resource
            env: In what environment is the data used (Json format)
                egg:
                {
                        "execution_time": "2023-07-12T12:00:00",
                        "tee": {
                           "type": "sgx2",
                           "mr_enclave": "#####"
                        }
                }
            global_attrs: Application-specific and data-independent attibutes (Json format)
                egg:
                {
                    "xgb": {
                        "tree_num": 1
                    }
                }
            resource_uris: list of Resource that need to be accessed,
                URI format: {data_uuid}/{partition_id}/{segment_id}
            columns: if this is a structued data, specify which columns will be used
            attrs: application-specific and data-dependent attributes (Json format)
                egg:
                {
                    "join": [
                        "join_key": ["id"],
                            "reference_key": {
                            "data_uuid": "t2",
                            "join_key": ["id"]
                            }
                    ]
                }
            cert_pems: cert chain of party
            private_key: private key of party

            Notice: len(resource_uris) = len(columns) = len(attrs)

        Returns:
            List[(bytes, bytes)]: The data keys in the list correspond one-to-one to the elements in the resource_uri
        """
        resource_request = capsule_manager_pb2.ResourceRequest()
        resource_request.initiator_party_id = initiator_party_id
        resource_request.scope = scope
        resource_request.op_name = op_name
        if env is not None:
            resource_request.env = env
        if global_attrs is not None:
            resource_request.global_attrs = global_attrs

        tool.assert_list_len_equal(
            resource_uris, columns, "len(resource_uris) != len(columns)"
        )
        tool.assert_list_len_equal(
            resource_uris, attrs, "len(resource_uris) != len(attrs)"
        )

        for index in range(len(resource_uris)):
            resource = resource_request.resources.add()
            resource.resource_uri = resource_uris[index]
            if columns is not None:
                resource.columns.extend(columns[index])
            if attrs is not None:
                resource.attrs = attrs[index]

        if private_key is None:
            # Generate temp RSA key-pair
            (private_key, cert_pems) = crypto.generate_rsa_keypair()

        # call authmanager service
        request = capsule_manager_pb2.GetDataKeysRequest()

        request.resource_request.CopyFrom(resource_request)
        if cert_pems is not None and len(cert_pems) > 0:
            request.cert = cert_pems[0].decode("utf-8")
        # Generate RA Report
        if not self.sim:
            digest = crypto.sha256(
                cert_pems[0],
                request.resource_request.SerializeToString(deterministic=True),
            )
            report = ual.create_report("Passport", tool.to_upper_hex(digest))
            request.attestation_report.CopyFrom(report)

        # encrypt request
        encrypted_response = self.stub.GetDataKeys(
            self.create_encrypted_request(
                request, self.get_public_key(), private_key, cert_pems
            )
        )
        if encrypted_response.status.code != 0:
            raise CapsuleManagerError(
                encrypted_response.status.code, encrypted_response.status.message
            )

        # decrypt request
        response = capsule_manager_pb2.GetDataKeysResponse()
        self.parse_from_encrypted_response(encrypted_response, private_key, response)

        return [
            (data_key.resource_uri, base64.b64decode(data_key.data_key_b64))
            for data_key in response.data_keys
        ]

    def create_data_keys(
        self,
        owner_party_id: str,
        resource_uris: List[str],
        data_keys: List[bytes],
        cert_pems: List[bytes] = None,
        private_key: Union[bytes, str, rsa.RSAPrivateKey] = None,
    ):
        """create data keys

        Args:
            owner_party_id: data owner
            resource_uris: list of Resource that need to be accessed,
                URI format: {data_uuid}/{partition_id}/{segment_id}
            data_keys: list of data_key for every resource_uri
            cert_pems: cert chain of party
            private_key: private key of party

            Notice: len(resource_uris) = len(data_keys)
        """
        request = capsule_manager_pb2.CreateDataKeysRequest()
        request.owner_party_id = owner_party_id

        tool.assert_list_len_equal(
            resource_uris, data_keys, "len(resource_uris) != len(data_keys)"
        )

        for uri, data_key in zip(resource_uris, data_keys):
            request.data_keys.add(
                resource_uri=uri,
                data_key_b64=base64.b64encode(data_key).decode("utf-8"),
            )

        if private_key is None:
            # Generate temp RSA key-pair
            (private_key, cert_pems) = crypto.generate_rsa_keypair()

        encrypted_response = self.stub.CreateDataKeys(
            self.create_encrypted_request(
                request, self.get_public_key(), private_key, cert_pems
            )
        )
        if encrypted_response.status.code != 0:
            raise CapsuleManagerError(
                encrypted_response.status.code, encrypted_response.status.message
            )

    def get_data_policys(
        self,
        owner_party_id: str,
        scope: str,
        cert_pems: List[bytes] = None,
        private_key: Union[bytes, str, rsa.RSAPrivateKey] = None,
    ) -> List[capsule_manager_pb2.Policy]:
        """create data policy

        Args:
            owner_party_id: data policy's owner
            scope: scope
            cert_pems: cert chain of party
            private_key: private key of party

        Returns:
            List[capsule_manager_pb2.Policy]: the list of policy
        """
        request = capsule_manager_pb2.ListDataPolicyRequest()
        request.owner_party_id = owner_party_id
        request.scope = scope

        if private_key is None:
            # Generate temp RSA key-pair
            (private_key, cert_pems) = crypto.generate_rsa_keypair()

        encrypted_response = self.stub.ListDataPolicy(
            self.create_encrypted_request(
                request, self.get_public_key(), private_key, cert_pems
            )
        )
        if encrypted_response.status.code != 0:
            raise CapsuleManagerError(
                encrypted_response.status.code, encrypted_response.status.message
            )
        # decrypt request
        response = capsule_manager_pb2.ListDataPolicyResponse()
        self.parse_from_encrypted_response(encrypted_response, private_key, response)

        return list(response.policies)

    def create_data_policy(
        self,
        owner_party_id: str,
        scope: str,
        data_uuid: str,
        rule_ids: List[str],
        grantee_party_ids: List[List[str]],
        columns: List[List[str]] = None,
        global_constraints: List[List[str]] = None,
        op_constraints_name: List[List[str]] = None,
        op_constraints_body: List[List[List[str]]] = None,
        cert_pems: List[bytes] = None,
        private_key: Union[bytes, str, rsa.RSAPrivateKey] = None,
    ):
        """create data policy

        Args:
            owner_party_id: data owner
            scope: scope
            data_uuid: data id
            rule_ids: list of rule
            grantee_party_ids: for every rule, the list of party ids being guanteed
            columns: for every rule, specify which columns can be used, if this is a structued data
            global_constraints: for every rule, gobal DSL decribed additional constraints
            op_constraints_name: for every rule, op name: e.g. PSI, XGB, LR, SQL
            op_constraints_body: for every rule, DSL decribed additional constraints, working on the specified operator.
            cert_pems: cert chain of party
            private_key: private key of party

        """
        request = capsule_manager_pb2.CreateDataPolicyRequest()
        request.owner_party_id = owner_party_id
        request.scope = scope
        request.policy.data_uuid = data_uuid

        tool.assert_list_len_equal(
            rule_ids, grantee_party_ids, "len(rule_ids) != len(grantee_party_ids)"
        )
        tool.assert_list_len_equal(rule_ids, columns, "len(rule_ids) != len(columns)")
        tool.assert_list_len_equal(
            rule_ids, global_constraints, "len(rule_ids) != len(global_constraints)"
        )
        tool.assert_list_len_equal(
            rule_ids, op_constraints_name, "len(rule_ids) != len(op_constraints_name)"
        )
        tool.assert_list_len_equal(
            rule_ids, op_constraints_body, "len(rule_ids) != len(op_constraints_body)"
        )

        for index in range(len(rule_ids)):
            rule = request.policy.rules.add()
            rule.rule_id = rule_ids[index]
            rule.grantee_party_ids.extend(grantee_party_ids[index])
            if columns is not None:
                rule.columns.extend(columns[index])
            if global_constraints is not None:
                rule.global_constraints.extend(global_constraints[index])
            if op_constraints_name is not None and op_constraints_body is not None:
                tool.assert_list_len_equal(
                    op_constraints_name[index],
                    op_constraints_body[index],
                    f"len(op_constraints_name[{index}]) != len(op_constraints_body[{index}])",
                )

                for name, constraint in zip(
                    op_constraints_name[index], op_constraints_body[index]
                ):
                    rule.op_constraints.add(op_name=name, constraints=constraint)
            elif op_constraints_name is not None:
                for name in op_constraints_name[index]:
                    rule.op_constraints.add(op_name=name, constraints=[])

        if private_key is None:
            # Generate temp RSA key-pair
            (private_key, cert_pems) = crypto.generate_rsa_keypair()

        encrypted_response = self.stub.CreateDataPolicy(
            self.create_encrypted_request(
                request, self.get_public_key(), private_key, cert_pems
            )
        )
        if encrypted_response.status.code != 0:
            raise CapsuleManagerError(
                encrypted_response.status.code, encrypted_response.status.message
            )

    def delete_data_policy(
        self,
        owner_party_id: str,
        scope: str,
        data_uuid: str,
        cert_pems: List[bytes] = None,
        private_key: Union[bytes, str, rsa.RSAPrivateKey] = None,
    ):
        """delete data policy

        Args:
            owner_party_id: data owner
            scope: scope
            data_uuid: data id
            cert_pems: cert chain of party
            private_key: private key of party

        """
        request = capsule_manager_pb2.DeleteDataPolicyRequest()
        request.owner_party_id = owner_party_id
        request.scope = scope
        request.data_uuid = data_uuid

        if private_key is None:
            # Generate temp RSA key-pair
            (private_key, cert_pems) = crypto.generate_rsa_keypair()

        encrypted_response = self.stub.DeleteDataPolicy(
            self.create_encrypted_request(
                request, self.get_public_key(), private_key, cert_pems
            )
        )
        if encrypted_response.status.code != 0:
            raise CapsuleManagerError(
                encrypted_response.status.code, encrypted_response.status.message
            )

    def add_data_rule(
        self,
        owner_party_id: str,
        scope: str,
        data_uuid: str,
        rule_id: str,
        grantee_party_ids: List[str],
        columns: List[str],
        global_constraints: List[str],
        op_constraints_name: List[str] = None,
        op_constraints_body: List[List[str]] = None,
        cert_pems: List[bytes] = None,
        private_key: Union[bytes, str, rsa.RSAPrivateKey] = None,
    ):
        """add data rule

        Args:
            owner_party_id: data owner
            scope: scope
            data_uuid: data id
            rule_id: identifier of the rule
            grantee_party_ids: the list of party ids being guanteed
            columns:  specify which columns can be used, if this is a structued data
            global_constraints: gobal DSL decribed additional constraints
            op_constraints_name: op name: e.g. PSI, XGB, LR, SQL
            op_constraints_body: DSL decribed additional constraints, working on the specified operator.
            cert_pems: cert chain of party
            private_key: private key of party

        """
        request = capsule_manager_pb2.AddDataRuleRequest()
        request.owner_party_id = owner_party_id
        request.data_uuid = data_uuid
        request.scope = scope
        request.rule.rule_id = rule_id
        request.rule.grantee_party_ids.extend(grantee_party_ids)

        tool.assert_list_len_equal(
            op_constraints_name,
            op_constraints_body,
            "len(op_constraints_name) != len(op_constraints_body)",
        )

        if columns is not None:
            request.rule.columns.extend(columns)
        if global_constraints is not None:
            request.rule.global_constraints.extend(global_constraints)
        if op_constraints_name is not None and op_constraints_body is not None:
            for name, constraint in zip(op_constraints_name, op_constraints_body):
                request.rule.op_constraints.add(op_name=name, constraints=constraint)

        if private_key is None:
            # Generate temp RSA key-pair
            (private_key, cert_pems) = crypto.generate_rsa_keypair()

        encrypted_response = self.stub.AddDataRule(
            self.create_encrypted_request(
                request, self.get_public_key(), private_key, cert_pems
            )
        )
        if encrypted_response.status.code != 0:
            raise CapsuleManagerError(
                encrypted_response.status.code, encrypted_response.status.message
            )

    def delete_data_rule(
        self,
        owner_party_id: str,
        scope: str,
        data_uuid: str,
        rule_id: str,
        cert_pems: List[bytes] = None,
        private_key: Union[bytes, str, rsa.RSAPrivateKey] = None,
    ):
        """delete data rule

        Args:
            owner_party_id: data owner
            scope: scope
            data_uuid: data id
            rule_id: identifier of rule
            cert_pems: cert chain of party
            private_key: private key of party

        """
        request = capsule_manager_pb2.DeleteDataRuleRequest()
        request.owner_party_id = owner_party_id
        request.scope = scope
        request.data_uuid = data_uuid
        request.rule_id = rule_id

        if private_key is None:
            # Generate temp RSA key-pair
            (private_key, cert_pems) = crypto.generate_rsa_keypair()

        encrypted_response = self.stub.DeleteDataRule(
            self.create_encrypted_request(
                request, self.get_public_key(), private_key, cert_pems
            )
        )
        if encrypted_response.status.code != 0:
            raise CapsuleManagerError(
                encrypted_response.status.code, encrypted_response.status.message
            )

    def get_export_data_key(
        self,
        request_party_id: str,
        resource_uri: str,
        data_export_certificate: str,
        cert_pems: List[bytes] = None,
        private_key: Union[bytes, str, rsa.RSAPrivateKey] = None,
    ) -> bytes:
        """get export data key

        Args:
            request_party_id: the request owner
            resource_uri: the identifier of resource
            data_export_certificate: Data Export Certificate, json format
                When the data request exporting party requests to obtain the decryption key
                for accessing the data, they need to obtain the signatures of all the
                original owners of the data, the request information, and the signature of
                the original owner, which together constitute the data export certificate.
        """
        request = capsule_manager_pb2.GetExportDataKeyRequest()
        request.request_party_id = request_party_id
        request.resource_uri = resource_uri
        request.data_export_certificate = data_export_certificate

        if private_key is None:
            # Generate temp RSA key-pair
            (private_key, cert_pems) = crypto.generate_rsa_keypair()

        encrypted_response = self.stub.GetExportDataKey(
            self.create_encrypted_request(
                request, self.get_public_key(), private_key, cert_pems
            )
        )
        if encrypted_response.status.code != 0:
            raise CapsuleManagerError(
                encrypted_response.status.code, encrypted_response.status.message
            )
        # decrypt request
        response = capsule_manager_pb2.GetExportDataKeyResponse()
        self.parse_from_encrypted_response(encrypted_response, private_key, response)
        return base64.b64decode(response.data_key.data_key_b64)

    def delete_data_key(
        self,
        owner_party_id: str,
        resource_uri: str,
        cert_pems: List[bytes] = None,
        private_key: Union[bytes, str, rsa.RSAPrivateKey] = None,
    ):
        """delete data key

        Args:
            owner_party_id: data owner
            resource_uri: the resource uri corresponding to the data key
            cert_pems: cert chain of party
            private_key: private key of party

        """
        request = capsule_manager_pb2.DeleteDataKeyRequest()
        request.owner_party_id = owner_party_id
        request.resource_uri = resource_uri

        if private_key is None:
            # Generate temp RSA key-pair
            (private_key, cert_pems) = crypto.generate_rsa_keypair()

        encrypted_response = self.stub.DeleteDataKey(
            self.create_encrypted_request(
                request, self.get_public_key(), private_key, cert_pems
            )
        )
        if encrypted_response.status.code != 0:
            raise CapsuleManagerError(
                encrypted_response.status.code, encrypted_response.status.message
            )
