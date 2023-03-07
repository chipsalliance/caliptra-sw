# file-header-fix

Used to ensure that all files contain the text "Licensed under the Apache-2.0
license" in the header. Similar to cargo fmt.

## Examples

### To check all files in the workspace:

```console
$ cd ~/projects/caliptra-sw
$ touch foo.rs bar.rs
$ cargo run -p file-header-fix -- --check
File "./bar.rs" doesn't contain "Licensed under the Apache-2.0 license" in the first 3 lines
File "./foo.rs" doesn't contain "Licensed under the Apache-2.0 license" in the first 3 lines
To fix, run "cargo run --bin file-header-fix" in the workspace directory.
$ echo $?
2
```

### To fix all files in the workspace automatically

```console
$ cd ~/projects/caliptra-sw
$ echo "fn main() {}" > foo.rs
$ touch bar.py
$ cargo run -p file-header-fix
$ cat foo.rs
// Licensed under the Apache-2.0 license

fn main() {}
$ cat bar.py
# Licensed under the Apache-2.0 license

```
