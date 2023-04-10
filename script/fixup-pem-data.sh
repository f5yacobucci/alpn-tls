#!/bin/bash

set -e

if [ ! -e $1 ]
then
  echo "Must provide a filename"
  exit 1
fi

echo; echo

awk 'NF {sub(/\r/, ""); printf "%s\\n",$0;}' $1

echo; echo
