#!/bin/bash

for i in {1..10}; do
  ./smartbugs -t slither -f samples/Split1/*
done

for i in {1..10}; do
  ./smartbugs -t slither -f samples/Split2/*
done

for i in {1..10}; do
  ./smartbugs -t slither -f samples/Split3/*
done

for i in {1..10}; do
  ./smartbugs -t slither -f samples/Split4/*
done
