# c103-tp-aya-sample

コミックマーケット103で参加するサークル「[御茶会と愉快な仲間たち](RustとeBPFでパケットをフィルタしてみよう)」のAriake Tea Party内記事「RustとeBPFでパケットをフィルタしてみよう」で登場するコードを掲載したリポジトリです。

## Prerequisites

1. Install bpf-linker: `cargo install bpf-linker`

## Build eBPF

```bash
cargo xtask build-ebpf
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag.

## Build Userspace

```bash
cargo build
```

## Run

```bash
RUST_LOG=info cargo xtask run
```
