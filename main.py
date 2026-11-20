#!/usr/bin/env python3
import re
import argparse
from itertools import cycle
from pathlib import Path
from datetime import datetime, timezone

BYTES_PER_LINE = 16
CHUNK_SIZE = 4096

def validate_input_path(path_str: str) -> Path:
    """Validates that the input path exists, points to a regular file, and that the file is non-empty.
    
    Args:
        path_str (str): The file path to the input file.
    
    Returns:
        Path: A Path object used when opening the input file.

    Raises:
        argparse.ArgumentTypeError: If the input file does not exist, is not a file, or if the file is empty.
    """
    path = Path(path_str)
    if not path.exists():
        raise argparse.ArgumentTypeError(f"Input file does not exist: '{path_str}'")
    if not path.is_file():
        raise argparse.ArgumentTypeError(f"Input path is not a file: '{path_str}'")
    if path.stat().st_size == 0:
        raise argparse.ArgumentTypeError(f"Input file is empty (0 bytes): '{path_str}'")
    return path

def validate_output_path(path_str: str) -> Path:
    """Validates that the output path is suitable for writing the encrypted data toc.
    
    Args:
        path_str (str): The file path to the output file.
    
    Returns:
        Path: A Path object used when writing the output file.
    
    Raises:
        argparse.ArgumentTypeError: If the output path is a directory, not a file or the output directory does not exist.
    """
    path = Path(path_str)
    if path.exists() and path.is_dir():
        raise argparse.ArgumentTypeError(f"Output path is a directory, not a file: '{path_str}'")
    if not path.parent.exists():
        raise argparse.ArgumentTypeError(f"Output directory does not exist: '{path.parent}'")
    return path

def parse_xor_key(raw_key: str) -> bytes:
    """Encodes a string XOR key as UTF-8 bytes.
    
    Args:
        raw_key (str): The UTF-8 string key.
    
    Returns:
        bytes: The encoded string as bytes.

    Raises:
        argparse.ArgumentTypeError: If the length of the key is not at least 1 byte.
    """
    if not raw_key:
        raise argparse.ArgumentTypeError("Key must be at least 1 byte")
    return raw_key.encode("utf-8")

def parse_xor_key_hex(raw_key: str) -> bytes:
    """Parses a hexadecimal XOR key into bytes.

    Accepts an optional ``0x`` prefix and spaces between hexadecimal bytes.

    Args:
        raw_key (str): The hexadecimal string key.
    
    Returns:
        bytes: The encoded hexadecimal string key as bytes.

    Raises:
        argparse.ArgumentTypeError: If the length of the key is not at least 1 byte or the string is not valid hexadecimal.
    """
    if not raw_key:
        raise argparse.ArgumentTypeError("Hex key must be at least 1 byte")

    # Allow spaces between hex bytes, e.g.:
    #   0xdeadbeef
    #   0xDE AD BE EF
    #   deadbeef
    #   DE AD BE EF
    hex_part = raw_key

    if hex_part.lower().startswith("0x"):
        hex_part = hex_part[2:]

    if not hex_part or not re.fullmatch(r"[0-9a-fA-F ]+", hex_part):
        raise argparse.ArgumentTypeError(
            f"Invalid hex key '{raw_key}': contains non-hex characters "
            "or invalid whitespace"
        )

    cleaned_key = hex_part.replace(" ", "")

    try:
        key_bytes = bytes.fromhex(cleaned_key)
    except ValueError as err:
        raise argparse.ArgumentTypeError(
            f"Invalid hex key '{raw_key}': must contain valid even-length hex digits"
        ) from err

    if not key_bytes:
        raise argparse.ArgumentTypeError("Hex key must be at least 1 byte")

    return key_bytes

def select_file_mode(output_format: str) -> str:
    """Returns the file-open mode appropriate for the selected output format.
    
    Args:
        output_format (str): The specified output format ('raw', 'python' or 'c').

    Returns:
        str: The prefered file-open mode for the given output format ('wb' or 'w').
    """
    return "wb" if output_format == "raw" else "w"

def setup_argparse() -> argparse.Namespace:
    """Parses and validates command-line arguments.
    
    Returns:
        argparse.Namespace: An object storing all the commandline arguments
    """
    parser = argparse.ArgumentParser(description=(
        "Applies an XOR key to binary shellcode file data and "
        "writes the encoded result to the selected output file, in raw, python or c style array format."
        )
    )

    # --key and --key-hex can not be used together
    key_group = parser.add_mutually_exclusive_group(required=True)

    key_group.add_argument(
        "-k",
        "--key",
        type=parse_xor_key,
        metavar="KEY",
        help="XOR key as a UTF-8 string (e.g 'sup3rSecret')"
    )

    key_group.add_argument(
        "-x",
        "--key-hex",
        type=parse_xor_key_hex,
        metavar="HEX_KEY",
        help="XOR key as hexadecimal bytes (e.g '0xdeadbeef', '0xDE AD BE EF', 'deadbeef', 'DE AD BE EF')",
    )

    parser.add_argument(
        "-i",
        "--input",
        type=validate_input_path,
        required=True,
        metavar="FILE",
        help="Input file path containing raw shellcode",
    )
    
    parser.add_argument(
        "-o",
        "--output",
        type=validate_output_path,
        required=True,
        metavar="FILE",
        help="Output file path to store the encrypted shellcode"
    )

    parser.add_argument(
        "-f",
        "--format",
        choices=["raw", "python", "c"],
        required=True,
        metavar="FORMAT",
        help="Specify the output format (raw, python or c style array)",
    )

    args = parser.parse_args()

    # Prevent accidentally truncating the input file by using it as output.
    if args.input.resolve() == Path(args.output).resolve():
        parser.error("Input and output paths cannot be the same file.")

    return args

def main():
    """Reads the input data and encrypts it using XOR, saving the encrypted data in the given format."""
    args = setup_argparse()

    key = args.key if args.key is not None else args.key_hex

    # NOTE: 
    # Keep the key stream across chunks so the repeating key does not
    # restart at each 4096-byte read.
    key_stream = cycle(key)

    # Reusable 4096 byte buffer
    buffer = bytearray(CHUNK_SIZE)

    with open(args.input, 'rb') as infile, open(args.output, select_file_mode(args.format)) as outfile:
        total_bytes = args.input.stat().st_size
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        # Write the header and variable declaration for formatted Python and C output.
        match args.format:
            case "python":
                outfile.write(
                    f"# Source: {args.input.name}\n"
                    f"# Size: {total_bytes} bytes\n"
                    f"# Generated at: {timestamp}\n\n"
                    "buf = bytearray(\n"
                )
            case "c":
                outfile.write(
                    f"// Source: {args.input.name}\n"
                    f"// Size: {total_bytes} bytes\n"
                    f"// Generated at: {timestamp}\n\n"
                    "unsigned char buf[] = {\n"
                )

        # Read and process the file in 4K chunks.
        while bytes_read := infile.readinto(buffer):
            
            # Zero-copy slice of only bytes read
            chunk = memoryview(buffer)[:bytes_read]

            # Encrypt the chunked buffer with the XOR key
            # Handles single-byte keys, repeating multi-byte keys and equal-length keys
            encrypted_data = bytes(byte ^ key for byte, key in zip(chunk, key_stream))

            match args.format:
                case "raw":
                    outfile.write(encrypted_data)
                case "python":
                    # Format and write 16 bytes per line as Python byte literals for a bytearray.
                    for i in range(0, len(encrypted_data), BYTES_PER_LINE):
                        line_bytes = encrypted_data[i:i + BYTES_PER_LINE]
                        hex_line = "".join(f"\\x{byte:02x}" for byte in line_bytes)
                        outfile.write(f'    b"{hex_line}"\n')
                case "c":
                    # Format and write 16 bytes per line as C hexadecimal array values.
                    for i in range(0, len(encrypted_data), BYTES_PER_LINE):
                        line_bytes = encrypted_data[i:i + BYTES_PER_LINE]
                        hex_line = ", ".join(f"0x{byte:02x}" for byte in line_bytes)
                        outfile.write(f"    {hex_line},\n")
        
        # Close the generated variable declaration once the array is fully written
        match args.format:
            case "python":
                outfile.write(")\n")
            case "c":
                outfile.write("};\n")

if __name__ == '__main__':
    main()
