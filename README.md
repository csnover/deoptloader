# De-Optloader

Unpacks OPTLOADER-packed 16-bit Windows executables.

Plus free bonus executable for listing Win16 New Executable resources!

## Releases

Prebuilt binaries for 64-bit Windows, macOS, and Linux are available from the
[releases page](https://github.com/csnover/deoptloader/releases).

## Running from source

1. Clone or download the repository in the usual manner
2. [Install Rust](https://www.rust-lang.org/learn/get-started)
3. Inside the repository directory, run `cargo run <path to executable>`.

## Limitations

This unpacker only generates unpacked executables that can be disassembled. The
generated executable may not actually run, nor is the loader fully stripped
out.

Patches to resolve these limitations are welcome.
