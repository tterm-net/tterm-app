# tTerm Web: shell integration for bash.
#
# tTerm Web writes this file each time it opens a terminal on this machine,
# and starts bash with it in place of the usual startup files:
#
#     bash --init-file ~/.tterm/bash.sh -i
#
# Edits made here by hand are overwritten. What it does, in order:
#
#   1. Reads a one-time key: the first line tTerm Web types. The terminal
#      starts with echo off, so the key never shows. Every marker carries it,
#      so nothing a program prints can pass for one.
#   2. Runs the startup files of a login shell, as plain `ssh` would.
#   3. Prints invisible markers: before each prompt, with the exit code, the
#      directory, the git branch and the PATH, and when a command starts,
#      with its text. tTerm Web takes them out of the stream; the screen
#      never shows them.

builtin read -r __tt_key
stty echo 2>/dev/null

# The functions come before the startup files, so that aliases those define
# cannot change how they read. `builtin` keeps functions of the same name
# out of the way.

# One marker: ESC ] 6973 ; key ; fields separated by ';' BEL. A field may
# hold anything, so the few bytes that would break the frame are written as
# %XX, and '%' itself too.
__tt_put() {
    builtin local out= f
    for f in "$@"; do
        f=${f//\%/%25}
        f=${f//;/%3B}
        f=${f//$'\a'/%07}
        f=${f//$'\e'/%1B}
        f=${f//$'\n'/%0A}
        f=${f//$'\r'/%0D}
        out+=";$f"
    done
    builtin printf '\033]6973;%s%s\007' "$__tt_key" "$out"
}

# The git branch at $PWD, into __tt_b, read from .git/HEAD without starting
# git: this runs before every prompt.
__tt_branch() {
    __tt_b=
    builtin local d="$PWD" h= g=
    while :; do
        if [ -f "$d/.git/HEAD" ]; then
            g=$d/.git
            break
        elif [ -f "$d/.git" ]; then
            # A worktree or a submodule: .git is a file naming the real one.
            builtin read -r h < "$d/.git"
            g=${h#gitdir: }
            case $g in /*) ;; *) g=$d/$g ;; esac
            break
        fi
        [ -n "$d" ] || return 0
        d=${d%/*}
    done
    [ -r "$g/HEAD" ] || return 0
    builtin read -r h < "$g/HEAD"
    case $h in
        "ref: refs/heads/"*) __tt_b=${h#ref: refs/heads/} ;;
        "ref: "*) __tt_b=${h#ref: } ;;
        *) __tt_b=${h:0:7} ;;
    esac
}

# A command starts: its text, as history recorded it, and how the command
# before it ended. Runs from PS0, in a subshell of its own, after the command
# is read and before it runs. Several commands on one line, or lines pasted
# together, get one of these each and a prompt only after the last, so the
# code of the one before has to come along here.
__tt_command() {
    builtin local e=$? h n
    case :$SHELLOPTS: in
        *:history:*) ;;
        *) __tt_put C "" "$e"; return ;;
    esac
    h=$(HISTTIMEFORMAT= builtin history 1)
    h=${h#"${h%%[! ]*}"}
    n=${h%%[!0-9]*}
    __tt_put C "${h:${#n}+2}" "$e"
}

# Before each prompt: how the last command ended and where the shell is now,
# with the PATH it finds commands in, for tTerm's own Tab.
__tt_prompt() {
    builtin local e=$? h n t p q
    # Commands that history was asked to skip are taken out again here; see
    # the history settings below for why they went in at all. A new entry is
    # told by its number, as `history 1` prints it: $HISTCMD would be
    # simpler, but bash 3.2, the one macOS has, keeps it at 1 in here.
    if [ -n "${__tt_skip_space-}" ] || [ -n "${__tt_skip_match-}" ]; then
        h=$(HISTTIMEFORMAT= builtin history 1)
        h=${h#"${h%%[! ]*}"}
        n=${h%%[!0-9]*}
        if [ -n "$n" ] && [ "$n" != "${__tt_hist-}" ]; then
            t=${h:${#n}+2}
            if [ -n "${__tt_skip_space-}" ] && [ "${t:0:1}" = " " ]; then
                builtin history -d "$n"
                n=$((n - 1))
            else
                # HISTIGNORE: patterns separated by ':'.
                p=${__tt_skip_match-}
                while [ -n "$p" ]; do
                    q=${p%%:*}
                    # shellcheck disable=SC2053
                    if [ -n "$q" ] && [ "$q" != "&" ] && [[ $t == $q ]]; then
                        builtin history -d "$n"
                        n=$((n - 1))
                        break
                    fi
                    [ "$q" != "$p" ] || break
                    p=${p#*:}
                done
            fi
        fi
        __tt_hist=$n
    fi
    __tt_history_settings
    __tt_branch
    h=${VIRTUAL_ENV-}
    __tt_put P "$e" "$PWD" "$HOME" "$__tt_b" "${h##*/}" "$PATH"
    return "$e"
}

# The marker takes a command's text from history, so a command that history
# skips (it starts with a space, or matches HISTIGNORE) would be recorded as
# the one before it. So history keeps every command, and the prompt takes
# out again those it was asked to skip, as soon as they finish. Checked
# before every prompt, so settings changed along the way are taken in too.
__tt_history_settings() {
    case :${HISTCONTROL-}: in
        *:ignorespace:* | *:ignoreboth:*)
            __tt_skip_space=1
            HISTCONTROL=${HISTCONTROL//ignoreboth/ignoredups}
            HISTCONTROL=${HISTCONTROL//ignorespace/}
            ;;
    esac
    if [ -n "${HISTIGNORE-}" ]; then
        __tt_skip_match=$HISTIGNORE
        HISTIGNORE=
    fi
}

export COLORTERM="${COLORTERM:-truecolor}"

# The startup files of a login shell, as bash itself would read them.
if [ -r /etc/profile ]; then
    . /etc/profile
fi
if [ -r ~/.bash_profile ]; then
    . ~/.bash_profile
elif [ -r ~/.bash_login ]; then
    . ~/.bash_login
elif [ -r ~/.profile ]; then
    . ~/.profile
fi

__tt_history_settings

# The markers: one before every prompt, one as every command starts. Ours go
# first, so they see the exit code before anything else can change it. PS0
# needs bash 4.4 or newer; older bash gets the prompt marker only, and
# tTerm Web then keeps no blocks for it.
if [[ $(builtin declare -p PROMPT_COMMAND 2>/dev/null) == "declare -a"* ]]; then
    PROMPT_COMMAND=(__tt_prompt "${PROMPT_COMMAND[@]}")
else
    PROMPT_COMMAND="__tt_prompt${PROMPT_COMMAND:+; $PROMPT_COMMAND}"
fi
PS0='$(__tt_command)'"${PS0-}"
# The last entry so far: what was there before this terminal stays.
__tt_hist=$(HISTTIMEFORMAT= builtin history 1)
__tt_hist=${__tt_hist#"${__tt_hist%%[! ]*}"}
__tt_hist=${__tt_hist%%[!0-9]*}
