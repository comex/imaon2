Required dependencies:

- nightly Rust/Cargo (won't build on stable)
- libclang 3.9 (for bindgen)
  - this ends up using clang-sys (https://github.com/KyleMayes/clang-sys)
  - see its README for how to specify the location

If you want yasce to use disassembly to fix jumps (which you do), you also need:

- LLVM
  - this can be separate from the LLVM used for libclang (lol Cargo)
  - uses llvm-sys (https://bitbucket.org/tari/llvm-sys.rs)
  - also, tables looks for llvm-tblgen in $PATH (todo)
- Node.js
  - looks for 'node' in $PATH, or override the command by setting the environment variable `NODE`

To build yasce,

    CARGO_TARGET_DIR=target cargo build --manifest-path src/yasce/Cargo.toml --features use_llvm --release

Or you could just `cd src/yasce && cargo build`, but using an environment variable keeps the dependencies in one location regardless of which crate you build.  (You can also build `exectool`.)

Omit `--features use_llvm` if you don't want to use LLVM, obviously; `--debug` instead of `--release` to make the build only take a long time rather than forever and ever.

## For development

Even though this isn't that large a repository, it's split rather liberally into crates in an attempt to improve compilation time.  Rather than manually write a large number of Cargo.tomls, I have a script (well, Rust program) to generate them all based on `extern crate` declarations and a common list of external dependencies.

Run the script with `cargo run --manifest-path build/gen-cargo-toml/Cargo.toml`; since I keep the output checked into Git, this isn't necessary if you're just trying to build.

The external dependencies are at `build/gen-cargo-toml/base.toml`.
