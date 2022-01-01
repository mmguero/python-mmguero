# mmguero

**mmguero** is my personal collection of miscellaneous helper functions for Python.

## Contents

* `AskForPassword` - get interactive password (without echoing)
* `AskForString` - get interactive user response
* `CheckOutputInput` - run command with arguments and return its exit code, stdout, and stderr
* `DoDynamicImport` - attempt dynamic imports, prompting for install via pip if possible
* `DownloadToFile` - download a URL to a local file
* `eprint` - print to stderr
* `GitClone` - create a local git clone
* `LoadStrIfJson` - is this string valid json? if so, load and return it
* `pushd` - chdir to directory as context manager, returning automatically
* `RemoveEmptyFolders` - recursively remove empty subfolders
* `RunProcess` - run command with arguments and return its exit code, stdout, and stderr
* `SizeHumanFormat` - nice human-readable file sizes
* `str2bool` - convenient boolean argument parsing
* `TestSocket` - test if a remote port is open
* `Which` - determine if a program/script exists and is executable in the system path
* `YesOrNo` - get interactive user response to Y/N question

## Installation

Using `pip`, to install the latest [release from PyPI](https://pypi.org/project/mmguero/):

```
python3 -m pip install -U mmguero
```

Or to install directly from GitHub:


```
python3 -m pip install -U 'git+https://github.com/mmguero/python-mmguero'
```

## Authors

* **Seth Grover** - *Initial work* - [mmguero](https://github.com/mmguero)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.