## Generating Templates

```
$ cargo build -p caliptra-x509 --features generate_templates
$ cd target/debug/build/caliptra-x509-[hash]/
$ mkdir target
$ OUT_DIR=target ./build-script-build
```

Generated templates in `target` can be copied to `x509/build`.
