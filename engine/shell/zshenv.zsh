# tTerm Web: shell integration for zsh, read first of its startup files.
#
# tTerm Web writes the files in this folder each time it opens a terminal on
# this machine, and starts zsh with ZDOTDIR pointing here:
#
#     ZDOTDIR=~/.tterm/zsh zsh -il
#
# Each of them runs the user's own file of the same name first, from where it
# really lives, so zsh starts as it always does; .zlogin, the last, hands
# ZDOTDIR back. Edits made here by hand are overwritten.
#
# What tTerm Web adds:
#   1. A one-time key: the first line tTerm Web types. The terminal starts
#      with echo off, so the key never shows. Every marker carries it, so
#      nothing a program prints can pass for one.
#   2. Invisible markers: before each prompt, with the exit code, the
#      directory, the git branch and the PATH, and when a command starts,
#      with its text. tTerm Web takes them out of the stream; the screen
#      never shows them.

if [[ -o interactive && -z ${__tt_key-} ]]; then
    builtin read -r __tt_key
    stty echo 2>/dev/null
    export COLORTERM="${COLORTERM:-truecolor}"

    # The functions come before the user's startup files, so that aliases
    # those define cannot change how they read.

    # One marker: ESC ] 6973 ; key ; fields separated by ';' BEL. A field
    # may hold anything, so the few bytes that would break the frame are
    # written as %XX, and '%' itself too.
    __tt_put() {
        builtin emulate -L zsh
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

    # The git branch at $PWD, into __tt_b, read from .git/HEAD without
    # starting git: this runs before every prompt.
    __tt_branch() {
        builtin emulate -L zsh
        typeset -g __tt_b=
        builtin local d=$PWD h= g=
        while true; do
            if [[ -f $d/.git/HEAD ]]; then
                g=$d/.git
                break
            elif [[ -f $d/.git ]]; then
                # A worktree or a submodule: .git is a file naming the real one.
                builtin read -r h < $d/.git
                g=${h#gitdir: }
                [[ $g == /* ]] || g=$d/$g
                break
            fi
            [[ -n $d ]] || return 0
            d=${d%/*}
        done
        [[ -r $g/HEAD ]] || return 0
        builtin read -r h < $g/HEAD
        case $h in
            ("ref: refs/heads/"*) __tt_b=${h#ref: refs/heads/} ;;
            ("ref: "*) __tt_b=${h#ref: } ;;
            (*) __tt_b=${h[1,7]} ;;
        esac
    }

    # Before each prompt: how the last command ended and where zsh is now,
    # with the PATH it finds commands in, for tTerm's own Tab.
    __tt_precmd() {
        builtin local e=$?
        __tt_branch
        __tt_put P "$e" "$PWD" "$HOME" "$__tt_b" "${VIRTUAL_ENV##*/}" "$PATH"
        return $e
    }

    # A command starts: its text as typed, history expanded (the full text
    # zsh is about to run when history is off), and how the one before it
    # ended.
    __tt_preexec() {
        builtin local e=$?
        __tt_put C "${1:-$3}" "$e"
    }
fi

typeset -g __tt_here=$ZDOTDIR
ZDOTDIR=${__tt_user_zdotdir:-$HOME}
if [[ -r $ZDOTDIR/.zshenv ]]; then
    builtin source "$ZDOTDIR/.zshenv"
fi
typeset -g __tt_user_zdotdir=$ZDOTDIR
ZDOTDIR=$__tt_here
