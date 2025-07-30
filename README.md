# mmguero

**mmguero** is my personal collection of miscellaneous helper functions for Python.

## Contents

* `AggressiveUrlEncode` - urlencode each character of a string
* `AppendToFile` - append strings to a text file
* `AskForPassword` - get interactive password (without echoing)
* `AskForString` - get interactive user response
* `AtomicInt` - atomic integer class and context manager
* `Base64DecodeIfPrefixed`- decode a string as base64 only if it starts with `base64:`, otherwise just return
* `CaselessDictionary` - dictionary that enables case insensitive searching while preserving case sensitivity when keys are listed
* `CheckOutputInput` - run command with arguments and return its exit code, stdout, and stderr
* `ChooseMultiple` - select multiple options from a list of options
* `ChooseOne` - select a single option from a list of options
* `ChownRecursive` - "chown -R" a file or directory
* `ClearScreen` - attempt to clear the screen with `clear` (\*NIX) or `cls` (Windows)
* `ContainsWhitespace` - check if any character in a string is whitespace
* `ContextLockedOrderedDict` - an OrderedDict that locks itself and unlocks itself as a context manager
* `CountLinesMmap` - use memory-mapped files and count "\n"
* `CustomMakeTranslation` - Replace substrings based on a dictionary of mappings
* `DeepGet` - safe deep get for a dictionary
* `DeepMerge` and `DeepMergeInPlace` - Recursively merges source dict into destination dict
* `DeepSet` - convenience routine for setting-getting a value into a dictionary
* `DictSearch` - recursive dictionary key search
* `DisplayMessage` - display a message to the user
* `DisplayProgramBox` - "stream" the contents of a file descriptor into a program box
* `DoDynamicImport` - attempt dynamic imports, prompting for install via pip if possible
* `DownloadToFile` - download a URL to a local file
* `eprint` - print to stderr
* `EscapeAnsi` - remove ANSI escape sequences
* `EVP_BytesToKey` - create key compatible with openssl enc
* `FileContents` - read the contents of a file, optionally falling back to binary
* `Flatten` - flatten a collection, but don't split strings
* `GetFunctionName` - return the name of a calling function as a string
* `GetIterable` - return an iterable for an iterable (as-is) or a scalar (as a single element in a tuple)
* `GetPrimaryIP` - return the primary IP (the one with a default route) on the local box
* `GitClone` - create a local git clone
* `JsonObjSerializer` - JSON serializer with better support for objects
* `LoadFileIfJson` - does this file contain valid json? if so, load and return it
* `LoadStrIfJson` - is this string valid json? if so, load and return it
* `PopLine` - "pop" lines from the beginning of a text file
* `pushd` - chdir to directory as context manager, returning automatically
* `RemoveEmptyFolders` - recursively remove empty subfolders
* `RemoveFalsy` - remove "empty" items from a collection
* `RemovePrefix` - remove a prefix from a string
* `RemoveSuffix` - remove a suffix from a string
* `RmtreeExcept` - recursively delete a directory tree while excluding specific files based on glob-style patterns
* `RunProcess` - run command with arguments and return its exit code, stdout, and stderr
* `RunSubProcess` - execute a shell process returning its exit code and output
* `SameFileOrDir` - return true if os.path.samefile, also False on exception
* `sha256sum` - calculate a sha256 hash of a file
* `shakeysum` - calculate shakey hash of a file
* `SizeHumanFormat` - nice human-readable file sizes
* `str2bool` and `str2boolorextra` - convenient boolean argument parsing
* `Tablify` - print a list of lists into a nice table
* `TemporaryFilename` - a context manager returning a temporary filename which is deleted upon leaving the context
* `TestSocket` - test if a remote port is open
* `Touch` - open a file and close it, updating its access time
* `val2bool` - convenient boolean argument parsing
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