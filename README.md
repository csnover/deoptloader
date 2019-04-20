# De-Optloader

Unpacks OPTLOADER-packed 16-bit Windows executables.

## Usage (from source)

1. Clone or download the repository in the usual manner
2. [Install Rust](https://www.rust-lang.org/learn/get-started)
3. From the root directory of the repository, run
   `cargo run <path to executable>`.

## Limitations

This unpacker only generates unpacked executables that can be disassembled. The
generated executable does not actually run, nor is the loader fully stripped
out.

Patches to resolve these limitations are welcome.
