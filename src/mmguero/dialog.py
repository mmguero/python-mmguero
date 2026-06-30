"""Interactive prompting: yes/no, free-text, password, single/multi-choice, and message dialogs, backed by pythondialog when available and falling back to stdin/stdout."""

import getpass
import os
import string
import sys

from enum import IntEnum, IntFlag, auto

from .platforms import PLATFORM_WINDOWS
from .clihints import _exclude_from_cli

_dialog = None
_main_dialog = None


def _dialog_init():
    """Lazily initialize the global pythondialog interface, falling back to None if the
    dialog package or binary is unavailable.
    """
    global _dialog
    global _main_dialog
    try:
        if not _dialog:
            from dialog import dialog as _dialog

        if not _main_dialog:
            _main_dialog = _dialog(dialog='dialog', autowidgetsize=True)
    except ImportError:
        _dialog = None
        _main_dialog = None


_dialog_init()


class UserInputDefaultsBehavior(IntFlag):
    """Flags controlling how interactive prompts (yes_or_no, ask_for_string, etc.) treat a default value.

    Attributes:
        DEFAULTS_PROMPT: Show the default value as a hint within the prompt text.
        DEFAULTS_ACCEPT: Accept the default value when the user provides no input.
        DEFAULTS_NON_INTERACTIVE: Combined with DEFAULTS_ACCEPT, skip prompting entirely and use the default.
    """

    DEFAULTS_PROMPT = auto()
    DEFAULTS_ACCEPT = auto()
    DEFAULTS_NON_INTERACTIVE = auto()


class UserInterfaceMode(IntFlag):
    """Flags selecting which interactive interface(s) a prompt may use.

    Attributes:
        INTERACTION_DIALOG: Use the pythondialog-based UI when available.
        INTERACTION_INPUT: Use stdin/stdout-based prompts.

    Values may be OR'd together so a prompt can fall back from one mode to the other.
    """

    INTERACTION_DIALOG = auto()
    INTERACTION_INPUT = auto()


class _DialogBackException(Exception):
    """Raised by prompt functions when the user selects the extra/back option."""

    pass


class _DialogCanceledException(Exception):
    """Raised by prompt functions when the user cancels or escapes a dialog."""

    pass


class BoolOrExtra(IntEnum):
    """Tri-state result for yes/no/extra-style prompts.

    Attributes:
        FALSE: The negative choice.
        TRUE: The affirmative choice.
        EXTRA: The extra/back choice.
    """

    FALSE = 0
    TRUE = 1
    EXTRA = 2


@_exclude_from_cli
def str2bool_or_extra(v):
    """Like str2bool, but also recognizes a third back/extra state.

    Args:
        v (str or bool): Value to interpret.

    Returns:
        BoolOrExtra: TRUE, FALSE, or EXTRA depending on `v`.

    Raises:
        ValueError: If `v` doesn't match a recognized value.
    """
    if isinstance(v, bool):
        return BoolOrExtra.TRUE if v else BoolOrExtra.FALSE
    elif isinstance(v, str):
        if v.lower() in ("yes", "true", "t", "y", "1"):
            return BoolOrExtra.TRUE
        elif v.lower() in ("no", "false", "f", "n", "0"):
            return BoolOrExtra.FALSE
        elif v.lower() in ("b", "back", "p", "previous", "e", "extra"):
            return BoolOrExtra.EXTRA
        else:
            raise ValueError("BoolOrExtra value expected")
    else:
        raise ValueError("BoolOrExtra value expected")


def clear_screen():
    """Attempt to clear the screen, silently ignoring failures."""
    try:
        os.system("clear" if sys.platform.lower() != PLATFORM_WINDOWS else "cls")
    except Exception:
        pass


@_exclude_from_cli
def yes_or_no(
    question,
    default=None,
    default_behavior=UserInputDefaultsBehavior.DEFAULTS_PROMPT,
    ui_mode=UserInterfaceMode.INTERACTION_DIALOG | UserInterfaceMode.INTERACTION_INPUT,
    clear_screen_after=False,
    yes_label='Yes',
    no_label='No',
    extra_label=None,
):
    """Get an interactive user response to a Y/N question.

    Args:
        question (str): The yes/no question to display.
        default (bool, optional): Default answer used when accepted or when running non-interactively.
        default_behavior (UserInputDefaultsBehavior, optional): Controls whether the default is shown as a prompt hint and/or auto-accepted. Defaults to DEFAULTS_PROMPT.
        ui_mode (UserInterfaceMode, optional): Which interface(s) to use: dialog, stdin input, or both. Defaults to both.
        clear_screen_after (bool, optional): Clear the screen after the prompt. Defaults to False.
        yes_label (str, optional): Label for the affirmative choice. Defaults to 'Yes'.
        no_label (str, optional): Label for the negative choice. Defaults to 'No'.
        extra_label (str, optional): If provided, adds a third extra/back choice. Defaults to None.

    Returns:
        bool: True for yes, False for no.

    Raises:
        _DialogBackException: If the user selects the extra/back option.
        RuntimeError: If neither the dialog UI nor stdin input is available.
    """
    result = None

    if (default is not None) and (
        (default_behavior & UserInputDefaultsBehavior.DEFAULTS_ACCEPT)
        and (default_behavior & UserInputDefaultsBehavior.DEFAULTS_NON_INTERACTIVE)
    ):
        reply = ""

    elif (ui_mode & UserInterfaceMode.INTERACTION_DIALOG) and (_main_dialog is not None):
        default_yes = (default is not None) and str2bool_or_extra(default)
        # by default the "extra" button is between "Yes" and "No" which looks janky, IMO.
        #   so we're going to switch things around a bit.
        yes_labelTmp = yes_label.capitalize() if default_yes else no_label.capitalize()
        no_labelTmp = no_label.capitalize() if default_yes else yes_label.capitalize()
        reply_map = {}
        if has_extra_label := (extra_label is not None):
            reply_map[_dialog.EXTRA] = _dialog.CANCEL
            reply_map[_dialog.CANCEL] = _dialog.EXTRA
        reply = _main_dialog.yesno(
            str(question),
            yes_label=str(yes_labelTmp),
            no_label=str(extra_label) if has_extra_label else str(no_labelTmp),
            extra_button=has_extra_label,
            extra_label=str(no_labelTmp) if has_extra_label else str(extra_label),
        )
        reply = reply_map.get(reply, reply)
        if default_yes:
            reply = 'y' if (reply == _dialog.OK) else ('e' if (reply == _dialog.EXTRA) else 'n')
        else:
            reply = 'n' if (reply == _dialog.OK) else ('e' if (reply == _dialog.EXTRA) else 'y')

    elif ui_mode & UserInterfaceMode.INTERACTION_INPUT:
        if (default is not None) and default_behavior & UserInputDefaultsBehavior.DEFAULTS_PROMPT:
            if str2bool_or_extra(default):
                question_str = f"\n{question} (Y{'' if yes_label == 'Yes' else ' (' + yes_label + ')'} / n{'' if no_label == 'No' else ' (' + no_label + ')'}): "
            else:
                question_str = f"\n{question} (y{'' if yes_label == 'Yes' else ' (' + yes_label + ')'} / N{'' if no_label == 'No' else ' (' + no_label + ')'}): "
        else:
            question_str = f"\n{question} (Y{'' if yes_label == 'Yes' else ' (' + yes_label + ')'} / N{'' if no_label == 'No' else ' (' + no_label + ')'}): "

        while True:
            reply = str(input(question_str)).lower().strip()
            if len(reply) > 0:
                try:
                    str2bool_or_extra(reply)
                    break
                except ValueError:
                    pass
            elif (default_behavior & UserInputDefaultsBehavior.DEFAULTS_ACCEPT) and (default is not None):
                break

    else:
        raise RuntimeError("No user interfaces available")

    if (len(reply) == 0) and (default_behavior & UserInputDefaultsBehavior.DEFAULTS_ACCEPT):
        reply = "y" if (default is not None) and str2bool_or_extra(default) else "n"

    if clear_screen_after is True:
        clear_screen()

    try:
        result = str2bool_or_extra(reply)
    except ValueError:
        result = yes_or_no(
            question,
            default=default,
            ui_mode=ui_mode,
            default_behavior=default_behavior - UserInputDefaultsBehavior.DEFAULTS_ACCEPT,
            clear_screen_after=clear_screen_after,
            yes_label=yes_label,
            no_label=no_label,
            extra_label=extra_label,
        )

    if result == BoolOrExtra.EXTRA:
        raise _DialogBackException(question)

    return bool(result)


@_exclude_from_cli
def ask_for_string(
    question,
    default=None,
    default_behavior=UserInputDefaultsBehavior.DEFAULTS_PROMPT,
    ui_mode=UserInterfaceMode.INTERACTION_DIALOG | UserInterfaceMode.INTERACTION_INPUT,
    clear_screen_after=False,
    extra_label=None,
):
    """Get an interactive user response (free-text string).

    Args:
        question (str): The prompt to display.
        default (str, optional): Default value used when accepted or when running non-interactively.
        default_behavior (UserInputDefaultsBehavior, optional): Controls whether the default is shown/auto-accepted. Defaults to DEFAULTS_PROMPT.
        ui_mode (UserInterfaceMode, optional): Which interface(s) to use. Defaults to both dialog and stdin.
        clear_screen_after (bool, optional): Clear the screen after the prompt. Defaults to False.
        extra_label (str, optional): If provided, adds an extra/back option. Defaults to None.

    Returns:
        str: The string entered by the user, or the default.

    Raises:
        _DialogCanceledException: If the user cancels the dialog.
        _DialogBackException: If the user selects the extra/back option.
        RuntimeError: If neither the dialog UI nor stdin input is available.
    """
    if (default is not None) and (
        (default_behavior & UserInputDefaultsBehavior.DEFAULTS_ACCEPT)
        and (default_behavior & UserInputDefaultsBehavior.DEFAULTS_NON_INTERACTIVE)
    ):
        reply = default

    elif (ui_mode & UserInterfaceMode.INTERACTION_DIALOG) and (_main_dialog is not None):
        code, reply = _main_dialog.inputbox(
            str(question),
            init=(
                default
                if (default is not None) and (default_behavior & UserInputDefaultsBehavior.DEFAULTS_PROMPT)
                else ""
            ),
            extra_button=(extra_label is not None),
            extra_label=str(extra_label),
        )
        if (code == _dialog.CANCEL) or (code == _dialog.ESC):
            raise _DialogCanceledException(question)
        elif code == _dialog.EXTRA:
            raise _DialogBackException(question)
        else:
            reply = reply.strip()

    elif ui_mode & UserInterfaceMode.INTERACTION_INPUT:
        reply = str(
            input(
                f"\n{question}{f' ({default})' if (default is not None) and (default_behavior & UserInputDefaultsBehavior.DEFAULTS_PROMPT) else ''}: "
            )
        ).strip()
        if (
            (len(reply) == 0)
            and (default is not None)
            and (default_behavior & UserInputDefaultsBehavior.DEFAULTS_ACCEPT)
        ):
            reply = default

    else:
        raise RuntimeError("No user interfaces available")

    if clear_screen_after is True:
        clear_screen()

    return reply


@_exclude_from_cli
def ask_for_password(
    prompt,
    default=None,
    default_behavior=UserInputDefaultsBehavior.DEFAULTS_PROMPT,
    ui_mode=UserInterfaceMode.INTERACTION_DIALOG | UserInterfaceMode.INTERACTION_INPUT,
    clear_screen_after=False,
    extra_label=None,
):
    """Get an interactive password (without echoing).

    Args:
        prompt (str): The prompt to display.
        default (str, optional): Default value used when accepted or when running non-interactively.
        default_behavior (UserInputDefaultsBehavior, optional): Controls whether the default is auto-accepted. Defaults to DEFAULTS_PROMPT.
        ui_mode (UserInterfaceMode, optional): Which interface(s) to use. Defaults to both dialog and stdin.
        clear_screen_after (bool, optional): Clear the screen after the prompt. Defaults to False.
        extra_label (str, optional): If provided, adds an extra/back option. Defaults to None.

    Returns:
        str: The password entered by the user, or the default.

    Raises:
        _DialogCanceledException: If the user cancels the dialog.
        _DialogBackException: If the user selects the extra/back option.
        RuntimeError: If neither the dialog UI nor stdin input is available.
    """
    if (default is not None) and (
        (default_behavior & UserInputDefaultsBehavior.DEFAULTS_ACCEPT)
        and (default_behavior & UserInputDefaultsBehavior.DEFAULTS_NON_INTERACTIVE)
    ):
        reply = default

    elif (ui_mode & UserInterfaceMode.INTERACTION_DIALOG) and (_main_dialog is not None):
        code, reply = _main_dialog.passwordbox(
            str(prompt),
            insecure=True,
            extra_button=(extra_label is not None),
            extra_label=str(extra_label),
        )
        if (code == _dialog.CANCEL) or (code == _dialog.ESC):
            raise _DialogCanceledException(prompt)
        elif code == _dialog.EXTRA:
            raise _DialogBackException(prompt)

    elif ui_mode & UserInterfaceMode.INTERACTION_INPUT:
        reply = getpass.getpass(prompt=f"{prompt}: ")

    else:
        raise RuntimeError("No user interfaces available")

    if clear_screen_after is True:
        clear_screen()

    return reply


@_exclude_from_cli
def choose_one(
    prompt,
    choices=[],
    default_behavior=UserInputDefaultsBehavior.DEFAULTS_PROMPT,
    ui_mode=UserInterfaceMode.INTERACTION_DIALOG | UserInterfaceMode.INTERACTION_INPUT,
    clear_screen_after=False,
    extra_label=None,
):
    """Choose one of many.

    Args:
        prompt (str): The prompt to display.
        choices (Iterable[tuple[str, str, bool]], optional): (tag, item, status) tuples; at most one `status` should be True to mark the default.
        default_behavior (UserInputDefaultsBehavior, optional): Controls whether the default is auto-accepted. Defaults to DEFAULTS_PROMPT.
        ui_mode (UserInterfaceMode, optional): Which interface(s) to use. Defaults to both dialog and stdin.
        clear_screen_after (bool, optional): Clear the screen after the prompt. Defaults to False.
        extra_label (str, optional): If provided, adds an extra/back option. Defaults to None.

    Returns:
        str: The tag of the chosen entry.

    Raises:
        _DialogCanceledException: If the user cancels the dialog.
        _DialogBackException: If the user selects the extra/back option.
        RuntimeError: If neither the dialog UI nor stdin input is available.
    """
    valid_choices = [x for x in choices if len(x) == 3 and isinstance(x[0], str) and isinstance(x[2], bool)]
    defaulted = next(iter([x for x in valid_choices if x[2] is True]), None)

    if (default_behavior & UserInputDefaultsBehavior.DEFAULTS_ACCEPT) and (
        default_behavior & UserInputDefaultsBehavior.DEFAULTS_NON_INTERACTIVE
    ):
        reply = defaulted[0] if defaulted is not None else ""

    elif (ui_mode & UserInterfaceMode.INTERACTION_DIALOG) and (_main_dialog is not None):
        code, reply = _main_dialog.radiolist(
            str(prompt),
            choices=valid_choices,
            extra_button=(extra_label is not None),
            extra_label=str(extra_label),
        )
        if code == _dialog.CANCEL or code == _dialog.ESC:
            raise _DialogCanceledException(prompt)
        elif code == _dialog.EXTRA:
            raise _DialogBackException(prompt)

    elif ui_mode & UserInterfaceMode.INTERACTION_INPUT:
        index = 0
        for choice in valid_choices:
            index = index + 1
            print(
                f"{index}: {choice[0]}{f' - {choice[1]}' if isinstance(choice[1], str) and len(choice[1]) > 0 else ''}"
            )
        while True:
            input_raw = input(
                f"{prompt}{f' ({defaulted[0]})' if (defaulted is not None) and (default_behavior & UserInputDefaultsBehavior.DEFAULTS_PROMPT) else ''}: "
            ).strip()
            if (
                (len(input_raw) == 0)
                and (defaulted is not None)
                and (default_behavior & UserInputDefaultsBehavior.DEFAULTS_ACCEPT)
            ):
                reply = defaulted[0]
                break
            elif (len(input_raw) > 0) and input_raw.isnumeric():
                input_index = int(input_raw) - 1
                if input_index > -1 and input_index < len(valid_choices):
                    reply = valid_choices[input_index][0]
                    break

    else:
        raise RuntimeError("No user interfaces available")

    if clear_screen_after is True:
        clear_screen()

    return reply


@_exclude_from_cli
def choose_multiple(
    prompt,
    choices=[],
    default_behavior=UserInputDefaultsBehavior.DEFAULTS_PROMPT,
    ui_mode=UserInterfaceMode.INTERACTION_DIALOG | UserInterfaceMode.INTERACTION_INPUT,
    clear_screen_after=False,
    extra_label=None,
):
    """Choose multiple of many.

    Args:
        prompt (str): The prompt to display.
        choices (Iterable[tuple[str, str, bool]], optional): (tag, item, status) tuples; `status` marks entries selected by default.
        default_behavior (UserInputDefaultsBehavior, optional): Controls whether the defaults are auto-accepted. Defaults to DEFAULTS_PROMPT.
        ui_mode (UserInterfaceMode, optional): Which interface(s) to use. Defaults to both dialog and stdin.
        clear_screen_after (bool, optional): Clear the screen after the prompt. Defaults to False.
        extra_label (str, optional): If provided, adds an extra/back option. Defaults to None.

    Returns:
        list[str]: Tags of the chosen entries (possibly empty).

    Raises:
        _DialogCanceledException: If the user cancels the dialog.
        _DialogBackException: If the user selects the extra/back option.
        RuntimeError: If neither the dialog UI nor stdin input is available.
    """
    valid_choices = [x for x in choices if len(x) == 3 and isinstance(x[0], str) and isinstance(x[2], bool)]
    defaulted = [x[0] for x in valid_choices if x[2] is True]

    if (default_behavior & UserInputDefaultsBehavior.DEFAULTS_ACCEPT) and (
        default_behavior & UserInputDefaultsBehavior.DEFAULTS_NON_INTERACTIVE
    ):
        reply = defaulted

    elif (ui_mode & UserInterfaceMode.INTERACTION_DIALOG) and (_main_dialog is not None):
        code, reply = _main_dialog.checklist(
            str(prompt),
            choices=valid_choices,
            extra_button=(extra_label is not None),
            extra_label=str(extra_label),
        )
        if code == _dialog.CANCEL or code == _dialog.ESC:
            raise _DialogCanceledException(prompt)
        elif code == _dialog.EXTRA:
            raise _DialogBackException(prompt)

    elif ui_mode & UserInterfaceMode.INTERACTION_INPUT:
        allowed_chars = set(string.digits + ',' + ' ')
        default_val_list_str = ",".join(defaulted)
        print("0: NONE")
        index = 0
        for choice in valid_choices:
            index = index + 1
            print(
                f"{index}: {choice[0]}{f' - {choice[1]}' if isinstance(choice[1], str) and len(choice[1]) > 0 else ''}"
            )
        while True:
            input_raw = input(
                f"{prompt}{f' ({default_val_list_str})' if (len(default_val_list_str) > 0) and (default_behavior & UserInputDefaultsBehavior.DEFAULTS_PROMPT) else ''}: "
            ).strip()
            if (
                (len(input_raw) == 0)
                and (len(defaulted) > 0)
                and (default_behavior & UserInputDefaultsBehavior.DEFAULTS_ACCEPT)
            ):
                reply = defaulted
                break
            elif input_raw == '0':
                reply = []
                break
            elif (len(input_raw) > 0) and (set(input_raw) <= allowed_chars):
                reply = []
                selected_indexes = list(set([int(x.strip()) - 1 for x in input_raw.split(',') if (len(x.strip())) > 0]))
                for idx in selected_indexes:
                    if idx > -1 and idx < len(valid_choices):
                        reply.append(valid_choices[idx][0])
                if len(reply) > 0:
                    break

    else:
        raise RuntimeError("No user interfaces available")

    if clear_screen_after is True:
        clear_screen()

    return reply


@_exclude_from_cli
def display_message(
    message,
    default_behavior=UserInputDefaultsBehavior.DEFAULTS_PROMPT,
    ui_mode=UserInterfaceMode.INTERACTION_DIALOG | UserInterfaceMode.INTERACTION_INPUT,
    clear_screen_after=False,
    extra_label=None,
):
    """Display a message to the user without expecting feedback.

    Args:
        message (str): Text to display.
        default_behavior (UserInputDefaultsBehavior, optional): Controls whether the message is auto-acknowledged in non-interactive mode. Defaults to DEFAULTS_PROMPT.
        ui_mode (UserInterfaceMode, optional): Which interface(s) to use. Defaults to both dialog and stdin.
        clear_screen_after (bool, optional): Clear the screen after the message is shown. Defaults to False.
        extra_label (str, optional): If provided, adds an extra/back option. Defaults to None.

    Returns:
        bool: True once the message has been acknowledged.

    Raises:
        _DialogCanceledException: If the user cancels the dialog.
        _DialogBackException: If the user selects the extra/back option.
    """
    reply = False

    if (default_behavior & UserInputDefaultsBehavior.DEFAULTS_ACCEPT) and (
        default_behavior & UserInputDefaultsBehavior.DEFAULTS_NON_INTERACTIVE
    ):
        reply = True

    elif (ui_mode & UserInterfaceMode.INTERACTION_DIALOG) and (_main_dialog is not None):
        code = _main_dialog.msgbox(
            str(message),
            extra_button=(extra_label is not None),
            extra_label=str(extra_label),
        )
        if (code == _dialog.CANCEL) or (code == _dialog.ESC):
            raise _DialogCanceledException(message)
        elif code == _dialog.EXTRA:
            raise _DialogBackException(message)
        else:
            reply = True

    else:
        print(f"\n{message}")
        reply = True

    if clear_screen_after is True:
        clear_screen()

    return reply


@_exclude_from_cli
def display_program_box(
    file_path=None,
    file_flags=0,
    file_descriptor=None,
    text=None,
    clear_screen_after=False,
    extra_label=None,
):
    """Display streaming content via _dialog.programbox.

    Args:
        file_path (str, optional): Path to a file to stream into the box.
        file_flags (int, optional): Flags used when opening `file_path` (e.g. os.O_* flags). Defaults to 0.
        file_descriptor (int, optional): An already-open file descriptor to stream from instead of `file_path`.
        text (str, optional): Static text to show instead of, or alongside, streamed content.
        clear_screen_after (bool, optional): Clear the screen after the box is closed. Defaults to False.
        extra_label (str, optional): If provided, adds an extra/back option. Defaults to None.

    Returns:
        bool: True if the box closed normally, or if no dialog UI is available.

    Raises:
        _DialogCanceledException: If the user cancels the dialog.
        _DialogBackException: If the user selects the extra/back option.
    """
    reply = False

    if _main_dialog is not None:
        code = _main_dialog.programbox(
            file_path=file_path,
            file_flags=file_flags,
            fd=file_descriptor,
            text=text,
            width=78,
            height=20,
            extra_button=(extra_label is not None),
            extra_label=str(extra_label),
        )
        if (code == _dialog.CANCEL) or (code == _dialog.ESC):
            raise _DialogCanceledException()
        elif code == _dialog.EXTRA:
            raise _DialogBackException()
        else:
            reply = True

            if clear_screen_after is True:
                clear_screen()

    return reply
