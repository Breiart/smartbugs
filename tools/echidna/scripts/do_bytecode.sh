#!/bin/sh

FILENAME="$1"


# TODO: Fix This Script


cd /MAIAN/tool
python3 maian.py -c 0 -bs "$FILENAME"
python3 maian.py -c 1 -bs "$FILENAME"
python3 maian.py -c 2 -bs "$FILENAME"
