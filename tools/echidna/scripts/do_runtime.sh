#!/bin/sh

FILENAME="$1"


# TODO: Fix This Script

cd /MAIAN/tool
python3 maian.py -c 0 -b "$FILENAME"
python3 maian.py -c 1 -b "$FILENAME"
python3 maian.py -c 2 -b "$FILENAME"
