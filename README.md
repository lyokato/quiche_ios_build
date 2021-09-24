# quiche-ios-build

Prepare quiche for iOS-build with prefixed-BoringSSL-symbols.

## Description

I'm assuming that you are trying to create a native library in Rust for iOS and want to use [quiche](https://github.com/cloudflare/quiche) in that library.

Since iOS development basically uses static libraries, there is a possibility of symbol duplication issues.

Specifically, the problem occurs when you are using another native network library and that library links to a different version of BoringSSL or OpenSSL.

Therefore, we will prepare an environment where QUICHE can be built with the prefix function provided in BoringSSL.
https://boringssl.googlesource.com/boringssl/+/HEAD/BUILDING.md#building-with-prefixed-symbols

## Usage

Specify the version of quiche you plan to include in your app as a parameter.

Also, specify either "arm64" or "x86_64" in the arch parameter.

```bash
python run.py --ver "0.10.0" --arch "arm64"
```

You can also specify a prefix for the symbol. If it is omitted, `QUICHE` is used as the prefix.

```bash
python run.py --ver "0.10.0" --arch "arm64" --prefix "MYAPP"
```

If you specify "arm64" for arch, the arm64 directory will be created.
If you specify "x86_64", a directory named x86_64 will be created.

In this directory, the quiche repository will be cloned, and libssl.a and libcrypt.a will be built with the prefix using the boringssl source included in the dependency. It will also replace the necessary parts of the quiche source code with PREFIXed symbols.

## Cargo.toml Example

Go to your Rust project where you are going to create a native library for iOS.
Assume that you have the following dependencies defined in your Cargo.toml file.

```toml
[dependencies]
quiche = "0.10.0"
foobar = "1.0"
```

Specify the quiche by path as follows.

```toml
[dependencies]
quiche = { path = "/path/to/this/repository/arm64/quiche" }
foobar = "1.0"
```

The value of path should be the directory of the quiche you have prepared using this repository.

It would be best if you could do this as follows, but the current specification of Cargo does not allow you to use the same library in different paths.

```toml
[target.aarch64-apple-ios.dependencies]
quiche = { path = "/path/to/this/repository/arm64/quiche" }

[target.x86_64-apple-ios.dependencies]
quiche = { path = "/path/to/this/repository/x86_64/quiche" }
```

Therefore, you need to rewrite the path each time you build for iOS arm64 or x86_64.


## Build with cargo

When running `cargo build` for iOS library generation, build with `QUICHE_BSSL_PATH` as shown below.

This feature of specifying boringssl by path is originally provided by quiche for windows, but this script is a patch to quiche's build script so that it can be used for iOS builds
This script patches the quiche build script so that it can be used for iOS builds.

#### for arm64

```
QUICHE_BSSL_PATH=/path/to/this/repository/arm64/quiche/deps/boringssl/src cargo build --target aarch64-apple-ios
```

#### for x86_64

```
QUICHE_BSSL_PATH=/path/to/this/repository/x86_64/quiche/deps/boringssl/src cargo build --target x86-64-apple-ios
```

## Pay Attention

This script will not work if the configuration of boringssl or quiche is changed.
Please be careful about the version you use.

### Supported Quiche Versions

- 0.10.0
- 0.9.0
- 0.8.1

