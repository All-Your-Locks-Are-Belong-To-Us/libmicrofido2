# Development

This document gives some pointers on where to start when modifying the library for your needs.

The starting point for a user is the [`fido.h`](include/fido.h), which includes most of the functionality exposed to the user.

When developing new features, you may orient on the [libfido2](https://github.com/Yubico/libfido2), which heavily inspired this project.

## Adding a new command

For our project, we only needed a small subset of the overall available commands in CTAP 2.1 and therefore only implemented those.
Nevertheless, the structure when adding a new command is fairly simple.

1. The flow starts with a function called like your commmand, [`fido_dev_get_assert`](https://github.com/All-Your-Locks-Are-Belong-To-Us/libmicrofido2/blob/bb3678d0ba02f4762fc2eea19a956f4b5342e706/src/assertion.c#L351).
1. This function can perform some input validation and finally call a `wait` function, [`fido_dev_get_assert_wait`](https://github.com/All-Your-Locks-Are-Belong-To-Us/libmicrofido2/blob/bb3678d0ba02f4762fc2eea19a956f4b5342e706/src/assertion.c#L322).
1. The `wait` function first calls the corresponding `tx` function to send the command to the authenticator ([`fido_dev_get_assert_tx`](https://github.com/All-Your-Locks-Are-Belong-To-Us/libmicrofido2/blob/bb3678d0ba02f4762fc2eea19a956f4b5342e706/src/assertion.c#L244)) and the `rx` function afterward to receive the response ([`fido_dev_get_assert_rx`](https://github.com/All-Your-Locks-Are-Belong-To-Us/libmicrofido2/blob/bb3678d0ba02f4762fc2eea19a956f4b5342e706/src/assertion.c#L290)).
1. The receiving function will then parse the CBOR encoded data and write the result into a stack-allocatable structure.

## Adding extensions and alike

As this library is designed without heap allocations and with as few copy operations as possible, we currently do not pass the extensions received from the authenticator in the `authenticatorGetInfo` command to the user directly.
Instead, we parse the extensions received from the authenticator into a bitfield.
To enable the parsing of a new extension, add the corresponding bitfield definition in [`info.h`](https://github.com/All-Your-Locks-Are-Belong-To-Us/libmicrofido2/blob/bb3678d0ba02f4762fc2eea19a956f4b5342e706/include/info.h#L23-L29), the string version at the top of the [`info.c`](https://github.com/All-Your-Locks-Are-Belong-To-Us/libmicrofido2/blob/bb3678d0ba02f4762fc2eea19a956f4b5342e706/src/info.c#L23-L28) and the parsing to the [`cbor_info_decode_extensions`](https://github.com/All-Your-Locks-Are-Belong-To-Us/libmicrofido2/blob/bb3678d0ba02f4762fc2eea19a956f4b5342e706/src/info.c#L123-L150) function.

The procedure for adding parsing support of other cryptographic algorithms, transports, etc. is similar.
