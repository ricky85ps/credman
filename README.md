# Credman
A little command line tool based on RustCrypto: RSA library

## Usage
To encrypt your secret just do

```bash
credman --input-data "My secret" --regenerate-priv-key
```
this will produce multiple files, including encrypted data, the private key in *postcard* and pem format
Without the `--regenerate-priv-key`, Credman would crash due to the fact, there is no private key file given.

For more help, please call `credman --help`.

## Motivation
I just wanted to create a RSA-Key as a binary blob, which I can include via `include_bytes!` macro. Credman is the
outcome and may be seen as feature complete. Nevertheless improvements are welcome.

## Possible Improvements
- [ ] Write some command line tests
- [ ] Introduce a state machine to cover e.g. a given public key only
- [ ] introduce other serde serializers and switch via command line paramter, maybe also configurable as package feature
