# XOR Shellcode Encoder

Supports UTF-8 string keys and hexadecimal keys, with three output formats:

- **Raw:** Write transformed bytes directly to a binary file.
- **Python:** Generate a Python `bytearray` declaration.
- **C:** Generate a C-style unsigned byte array declaration.

Input data is processed in chunks rather than loaded entirely into memory, making the utility suitable for larger binary files.

> **Disclaimer:** This utility performs a repeating-key XOR transformation. It is not cryptographically secure encryption.

## Requirements

- Python 3.10 or newer.
- No third-party dependencies (Python standard library only).

## Usage

```bash
python xorcrypter.py -k KEY -i INPUT -o OUTPUT -f FORMAT
```

Alternatively, supply a hexadecimal key:

```bash
python xorcrypter.py -x HEX_KEY -i INPUT -o OUTPUT -f FORMAT
```

### Arguments

| Argument | Description |
|---|---|
| `-k`, `--key` | XOR key supplied as a UTF-8 string |
| `-x`, `--key-hex` | XOR key supplied as hexadecimal bytes |
| `-i`, `--input` | Input file containing binary data |
| `-o`, `--output` | Output file |
| `-f`, `--format` | Output format: `raw`, `python`, or `c` |
| `-h`, `--help` | Display help and available arguments |

**Key arguments are mutually exclusive.** Use either `--key` or `--key-hex`, not both.

## XOR Key Formats

### String key

Use `--key` to supply a normal string.

```bash
python xorcrypter.py \
    --key "sup3rSecret" \
    --input payload.bin \
    --output encrypted.bin \
    --format raw
```

The supplied string is encoded using UTF-8 before being used as the XOR key.

For example:

```text
Input string:  ABC
UTF-8 bytes:   41 42 43
```

### Hexadecimal key

Use `--key-hex` when you want to supply the key directly as hexadecimal bytes.

```bash
python xorcrypter.py \
    --key-hex "deadbeef" \
    --input payload.bin \
    --output encrypted.bin \
    --format raw
```

The hexadecimal parser accepts an optional `0x` prefix and spaces between hexadecimal bytes.

All of the following represent the same key:

```text
deadbeef
0xdeadbeef
DE AD BE EF
0xDE AD BE EF
```

Resulting bytes:

```text
DE AD BE EF
```

Hexadecimal keys must contain a non-zero, even number of hexadecimal digits.

## Output Formats

### Raw (`raw`)

Writes the transformed bytes directly to an output file.

```bash
python xorcrypter.py \
    -k "secret" \
    -i payload.bin \
    -o encrypted.bin \
    -f raw
```

Useful when the output needs to remain binary data.

### Python (`python`)

Generates a Python `bytearray` declaration containing the transformed data.

```bash
python xorcrypter.py \
    -k "secret" \
    -i payload.bin \
    -o payload.py \
    -f python
```

Example output:

```python
# Source: payload.bin
# Size: 32 bytes
# Generated at: 2026-11-20 02:40:00 UTC

buf = bytearray(
    b"\x01\x02\x03\x04"
    b"\x05\x06\x07\x08"
)
```

The resulting declaration can be used directly in another Python program.

### C (`c`)

Generates a C-style unsigned byte array.

```bash
python xorcrypter.py \
    -k "secret" \
    -i payload.bin \
    -o payload.h \
    -f c
```

Example output:

```c
// Source: payload.bin
// Size: 32 bytes
// Generated at: 2026-11-20 02:40:00 UTC

unsigned char buf[] = {
    0x01, 0x02, 0x03, 0x04,
    0x05, 0x06, 0x07, 0x08,
};
```

The generated declaration can be included in a C/C++ project.

## How It Works

The utility applies XOR between each input byte and the corresponding byte in a repeating key.

For example, given the following data and key:

```text
Data:  01 02 03 04 05 06
Key:   AA BB
```

The operation becomes:

```text
01 ^ AA
02 ^ BB
03 ^ AA
04 ^ BB
05 ^ AA
06 ^ BB
```

The key repeats continuously until all input data has been processed.

### Chunked Processing

Input data is processed in chunks of 4096 bytes.

```text
          Input file
              |
              v
       +--------------+
       |  4096 bytes  |
       +--------------+
              |
              v
       +--------------+
       | XOR transform|
       +--------------+
              |
              v
          Output file
              |
              v
       +--------------+
       |  Next chunk  |
       +--------------+
              |
              v
          Repeat...
```

The XOR key iterator is initialized once and maintained across all chunks. This ensures that the key sequence does not restart at the beginning of each read.

A reusable buffer is used to avoid repeatedly allocating input buffers.

## Input Validation

The utility performs several checks before processing:

- Input file must exist.
- Input path must refer to a regular file.
- Input file cannot be empty.
- Output path cannot refer to an existing directory.
- Output directory must already exist.
- Input and output paths cannot resolve to the same path.
- Exactly one XOR key argument must be supplied.
- Hexadecimal keys must contain valid hexadecimal characters and an even number of digits.

## Help

For a complete overview of available arguments:

```bash
python xorcrypter.py --help
```
