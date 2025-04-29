# `ogaki`

> "ogaki" (御幾) that referred to notice boards or public signboards in ancient
> Japan. Ogaki served as an important means of communication and spreading
> information to the common people before newspapers and mass media existed.

## CLI Reference

``` sh
ogaki --help
```

```
Utility for automatic update-n-start processes of LRC20d binaries.


Usage: ogaki <COMMAND>

Commands:
  update                Check for lrc20d updates and install them
  check-updates         Check for lrc20d updates
  run-with-auto-update  Run lrc20d, automatically checking for updates and installing them
  help                  Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

## Build container with `ogaki` and `lrc20d`

Checkout the infrastructure's **Build** section at
[README](../../infrastructure/README.md) to locally build fully functional
upgredable node.
