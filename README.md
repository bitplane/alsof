# 📂 `lsoph`

TUI that lists open files for a given process.

Usage:

```shell
uvx lsoph -p <pid>
```

## Backends

`strace` is the default and best supported at the moment.

| name      | OS       | Active | Notes                                       |
|-----------|----------|--------|---------------------------------------------|
| `strace`  | 🐧       |   ✅   | Might require root                          |
| `psutil`  | 🐧🍏🪟👿 |   ❌   | Can only track open files                   |
| `lsof`    | 🐧🍏👿   |   ❌   | Ditto                                       |


## Future?

* `dtrace` for BSD/Mac
* `ps_mon` for Mac
* `inotify` for Linux
* `Win32`

* [🎬 demo](https://asciinema.org/a/c7T8id39jU7ap6E0D99S5dJ6F)
* [🏠 home](https://bitplane.net/dev/python/lsoph)
* [🐱 github](https://github.com/bitplane/lsoph)
* [🐍 pypi](https://pypi.org/project/lsoph)

