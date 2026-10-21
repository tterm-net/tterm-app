# tTerm Web: the user's own .zprofile, from where it really lives.
# See .zshenv in this folder for what these files are.
ZDOTDIR=$__tt_user_zdotdir
if [[ -r $ZDOTDIR/.zprofile ]]; then
    builtin source "$ZDOTDIR/.zprofile"
fi
__tt_user_zdotdir=$ZDOTDIR
ZDOTDIR=$__tt_here
