# CapsuleManager SDK

CapsuleManager sdk offers several apis to access CapsuleManager Service, which is designed to manage metadata of user data and authorization information.

## Features

There are two ways to use CapsuleManager SDK:

- If you will use sdk in source code, then you can just call functions defined in file python/sdc/capsule_manager_frame.py
- If you will use sdk in terminal, then you can use three commands:cms, cms_util, cms_config

## Quick Start

### Glossary

- CMS: Capsule Manager Service
- Party: the user of Capsule Manager SDK
- Resource: usually refers to data
- Data Policy: some rules that restrict access to data, usually related to permissions

### Install

```bash
pip install capsule-manager-sdk
```

### Use sdk in source code

You can just call functions defined in file python/sdc/capsule_manager_frame.py. The function is as follows:

- get_public_key: get CMS public key
- register_cert: register cert of Party in CMS
- get_data_keys: get data keys of some Resources according to the data policy from CMS
- register_data_keys: upload data keys of some Resources to CMS
- get_data_policys: get Data Policy of some Resources from CMS
- register_data_policy: upload Data Policy of some Resources to CMS
- delete_data_policy: delete Data Policy of some Resources to CMS
- add_data_rule: for one Data Policy, add rules for it
- delete_data_rule: for one Data Policy, delete rules for it
- get_export_data_key: get data key for data generated from multiple datas which belong to different Partys, usually involving different Party's approval
- delete_data_key: delete data key of a specific Resource from CMS

example:

```bash
from sdc.capsule_manager_frame import CapsuleManagerFrame

auth_frame = CapsuleManagerFrame(
    "127.0.0.1:8888",
    "1083D6017E951017EB29611024D63D4DF73445DD880D1151E776541FEBE4A776",
    None,
    True,
)
public_key_pem = auth_frame.get_public_key()
print(public_key_pem)
```

For more examples please see file python/tests/test_capsule_manager.py

### Use sdk in terminal

There are three commands in terminal, the commands are following:

- cms: according to the config file, call functions in file python/sdc/capsule_manager_frame.py.
- cms_config: help generate the config file which will be used in cms command
- cms_util: offer several convenient subcommands to use

#### Introduction to command cms

Command cms is the main command, it includes several subcommands which are following:

```bash
cms --help
```

```bash
Usage: cms [OPTIONS] COMMAND [ARGS]...

Options:
  --config-file TEXT  the config path
  --help              Show this message and exit.

Commands:
  add-data-rule         add data rule for a specific...
  delete-data-key       delete the data key of a...
  delete-data-policy    delete data policy of a...
  delete-data-rule      delete data rule for a...
  get-data-keys         get data_keys of several...
  get-data-policys      get data policy of the party...
  get-export-data-key   get the data key of export...
  get-public-key        get the pem format of public...
  register-cert         upload the cert of party...
  register-data-keys    upload data_keys of several...
  register-data-policy  upload data policy of a...

```

If you want to know what subcommands or parameters are supported, just use --help

```bash
# view supported subcommands
cms --help
# view supported parameters
cms --config-file=cli/cms/cli.yaml delete-data-rule --help
```

- config-file: the path of config file, we will explain it in the cms_config section
- commands: each command call one corresponding function in file python/sdc/capsule_manager_frame.py. I believe you can distinguish them from their names, for example, command get-public-key is calling function get_public_key

    ```bash
    cms --config-file=cli/cms/cli.yaml get-public-key
    # this will print public-key

    ```

### Introduction to the config file

There are three parts in the config file python/cli/cli-template.yaml.

- main section: it will be used to instantiate class CapsuleManagerFrame defined in file python/sdc/capsule_manager_frame.py

    ```bash
    host: "127.0.0.1"
    mr_enclave: ""
    sim: true
    root_ca_file: null
    private_key_file: null
    # List[str], cert chain file
    cert_chain_file: null
    ```

- common section: the common config of function part

    ```bash
    common:
    # str
    party_id: "alice"
    # List[str], cert chain file
    cert_pems_file: null
    # str
    scheme: "RSA"
    # file contains private key
    private_key_file: null
    ```

- function section: each section corresponds to a function call. for example, the fuction create_data_keys. As you can see, the configuration corresponds to the function parameters one-to-one.(of course, there are some function parameters in the common section)

    ```bash
        # function defination
        def create_data_keys(
            self,
            owner_party_id: str,
            resource_uris: List[str],
            data_keys: List[bytes],
            cert_pems: List[bytes] = None,
            private_key: Union[bytes, str, rsa.RSAPrivateKey] = None,
        ):

        # the function part of the config file
        register_data_keys:
            # List[str]
            resource_uris:
            # List[bytes]
            data_key_b64s:

    ```

After the above explanation, you should understand the design concept of this configuration file, but there are two points to note:

1. If the content of a configuration field is too long, it will be changed to read from a file. for example, the RSA key pair:

    ```bash
    root_ca_file: null
    private_key_file: null
    cert_chain_file: null
    ```

2. If the type of the content of a configuration field cannot be represented by a string, it will be changed to be represented by a string. for example, the type of data key is bytes, we will base64 encode it

    ```bash
    # List[bytes]
    data_key_b64s:
    ```

so, How to modify the configuration file by cms_config command?

### Introduction to command cms_config

Command cms_config help modify the config file python/cli/cli-template.yaml which will be used in cms command

Command cms_config is the main command, it includes several subcommands which are following:

```bash
cms_config --help
```

```bash
Usage: cms_config [OPTIONS] COMMAND [ARGS]...

Options:
  --config-file TEXT  config file path
  --help              Show this message and exit.

Commands:
  add-data-rule
  common
  create-data-policy
  delete-data-policy
  delete-data-rule
  get-data-keys
  get-data-policys
  init
```

If you want to know what subcommands or parameters are supported, just use --help

```bash
# view supported subcommands
cms_config --help
# view supported parameters
cms_config --config-file=cli/cms/cli.yaml init --help
```

Since cms_config modifies the config file and the config file has three sections, so the corresponding cms_config has three types of subcommands.

- init: modify the main section of config file

```bash
cms_config --config-file=cli/cms/cli.yaml init
```

- common: modify the common section of config file

```bash
cms_config --config-file=cli/cms/cli.yaml common
```

- fuctuion: modify the fuction section of config file. for example, delete-data-rule

```bash
cms_config --config-file=cli/cms/cli.yaml delete-data-rule
```

Please note that some parameters cannot be modified via the command cms_config, this is because we follow two principles:

1. if the parameter type is list, it cannot be modified through the command line because [click](https://click.palletsprojects.com/en/8.1.x/) does not support nested lists.

2. if the parameter content is too long, we do not support passing it in through the command line.

### Introduction to command cms_util

Command cms_util offers several convenient subcommands to use

```bash
cms_util --help
```

```bash
Usage: cms_util [OPTIONS] COMMAND [ARGS]...

Options:
  --help  Show this message and exit.

Commands:
  decrypt-file               decrypt file using data key
  decrypt-file-inplace       decrypt file inplace...
  encrypt-file               encrypt file using data key
  encrypt-file-inplace       encrypt file inplace...
  generate-data-export-cert  generate the vote result...
  generate-data-key-b64      generate the base64...
  generate-party-id          generate the party id...
  generate-rsa-keypair       generate rsa key pair...
```

If you want to know what subcommands or parameters are supported, just use --help

```bash
# view supported subcommands
cms_util --help
# view supported parameters
cms_config decrypt-file --help
```

for command cms_util, just use it. for example

```bash
cms_util generate-data-key-b64
# output
emK2Imaz9f6nZNWO2hBjdA==
```

For most functions, you can tell what they do by their names.
For a small number of functions that are difficult to understand, here is a detailed description.

- generate-data-key-b64: generate data key and encode it with base64

- generate-party-id: generate the identifier of party based on its certificate

- merge-cert-chain-files: merge multiple certificate files into a certificate chain file. Note that the order of the certificates is important. The last certificate is the CA.

- generate-data-export-cert: when exporting data, data participants are required to vote whether to agree to the data export. This function is used to generate the voting results. Since the voting results are more complicated, there is also a file python/cli/data-export-template.yaml to help generate the voting results.

The design idea of this file python/cli/data-export-template.yaml is consistent with the previous file python/cli/cli-template.yaml and is not difficult to understand.

```bash
vote_request:
  vote_request_id:
  type:
  initiator:
  vote_counter:
  voters:
    -
  executors:
    -
  approved_threshold:
  approved_action:
  rejected_action:
  # List[str], cert chain file
  cert_chain_file:
  private_key_file:
  vote_request_signature:

vote_invite:
  -
    vote_request_id:
    voter:
    action:
    # List[str], cert chain file
    cert_chain_file:
    private_key_file:
    voter_signature:

```

## License

This project is licensed under the [Apache License](LICENSE)
