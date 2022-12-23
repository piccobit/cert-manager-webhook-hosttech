#!/bin/bash

bump_mode=$(git log -1 --pretty=format:'%s%n' | awk 'match($0, /\[(PREPATCH|PATCH|PREMINOR|MINOR|PREMAJOR|MAJOR)\]/, a) {printf("%s\n", tolower(a[1]))}')
tmp_preid=$(git log -1 --pretty=format:'%s%n' | awk 'match($0, /\[(RELEASE|PRERELASE|DEBUG)\]/, a) {printf("%s\n", tolower(a[1]))}')

case $tmp_preid in

  release)
    preid=""
    ;;

  debug)
    preid="dbg"
    ;;

  prerelease)
    preid="rc"
    ;;

  *)
    preid=""
    ;;
esac


echo "bump_mode=$bump_mode"
echo "preid=$preid"
