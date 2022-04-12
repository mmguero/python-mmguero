# mmguero

**mmguero** is my personal collection of miscellaneous helper functions for Python.

## Contents

* `AskForPassword` - get interactive password (without echoing)
* `AskForString` - get interactive user response
* `Base64DecodeIfPrefixed`- decode a string as base64 only if it starts with `base64:`, otherwise just return
* `CaselessDictionary` - dictionary that enables case insensitive searching while preserving case sensitivity when keys are listed
* `CheckOutputInput` - run command with arguments and return its exit code, stdout, and stderr
* `ChooseMultiple` - select multiple options from a list of options
* `ChooseOne` - select a single option from a list of options
* `ClearScreen` - attempt to clear the screen with `clear` (\*NIX) or `cls` (Windows)
* `DeepGet` - safe deep get for a dictionary
* `DoDynamicImport` - attempt dynamic imports, prompting for install via pip if possible
* `DownloadToFile` - download a URL to a local file
* `eprint` - print to stderr
* `GetIterable` - return an iterable for an iterable (as-is) or a scalar (as a single element in a tuple)
* `GitClone` - create a local git clone
* `LoadFileIfJson` - does this file contain valid json? if so, load and return it
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