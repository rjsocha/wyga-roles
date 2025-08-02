# This file is managed by ansible - use .bashrc.local for local changes
#
# ~/.bashrc: executed by bash(1) for non-login shells.

# If not running interactively, don't do anything
case $- in
    *i*) ;;
      *) return;;
esac

[[ -s ~/.bashrc.managed ]] && source ~/.bashrc.managed  || true
[[ -s ~/.bashrc.local   ]] && source ~/.bashrc.local    || true

# END OF MANAGED FILE
