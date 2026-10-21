# tTerm Web: the user's own .zshrc, from where it really lives, and then
# the markers. See .zshenv in this folder for what these files are.
ZDOTDIR=$__tt_user_zdotdir
if [[ -r $ZDOTDIR/.zshrc ]]; then
    builtin source "$ZDOTDIR/.zshrc"
fi
__tt_user_zdotdir=$ZDOTDIR
ZDOTDIR=$__tt_here

# The system's zshrc ran while ZDOTDIR pointed here, and on macOS it sets
# HISTFILE from it: history belongs with the user's own files.
if [[ $HISTFILE == $__tt_here/* ]]; then
    HISTFILE=$__tt_user_zdotdir/${HISTFILE:t}
fi

# Ours go first in line, so they see the exit code before anything else can
# change it, whatever the user's own hooks are.
if (( ${+functions[__tt_precmd]} )); then
    precmd_functions=(__tt_precmd ${precmd_functions:#__tt_precmd})
    preexec_functions=(__tt_preexec ${preexec_functions:#__tt_preexec})
fi
