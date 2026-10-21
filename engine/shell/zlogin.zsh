# tTerm Web: the user's own .zlogin, from where it really lives, the last
# of the startup files. See .zshenv in this folder for what these files are.
ZDOTDIR=$__tt_user_zdotdir
if [[ -r $ZDOTDIR/.zlogin ]]; then
    builtin source "$ZDOTDIR/.zlogin"
fi
# From here on zsh is the user's own: shells started from it read the user's
# startup files, not these.
if [[ $ZDOTDIR == "$HOME" ]]; then
    unset ZDOTDIR
fi
unset __tt_here __tt_user_zdotdir
