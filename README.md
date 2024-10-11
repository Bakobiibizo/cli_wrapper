# Communex CLI wrapper

This is a cli wrapper for the communex cli. It is used the maintain an encrypted key for your commune key.

## Key Features

1. Encrypt and decrypt your commune key to safely store it and only unlock it when needed.
2. Interactive cli with the same commands as the communex cli.
3. The executable binary accepts command line arguments for encrypting and decrypting your key without the need to run the cli interactively.

## Installation

1. Download the binary from the [releases page](https://github.com/bakobiibizo/cli-wrapper/releases)
2. Make the binary executable
```bash
chmod +x cli-wrapper
```

3. Move the binary to a directory in your PATH, for example:
```bash
sudo mv cli-wrapper /usr/local/bin/
```

## Usage

```bash
./cli-wrapper
```

You will be prompted to enter your password and then the cli will start.

## Encrypting and Decrypting
To encrypt your key, run the following command:
```bash
./cli-wrapper KEYNAME encrypt
```

To decrypt your key, run the following command:
```bash
./cli-wrapper KEYNAME decrypt
```



