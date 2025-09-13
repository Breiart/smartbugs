#!/bin/bash


./smartbugs -t slither -f samples/Split1/* --time-budget 600

./smartbugs -t slither -f samples/Split1/* --time-budget 1200

./smartbugs -t slither -f samples/Split1/* --time-budget 1800

#./smartbugs -t slither -f samples/Split1/* --time-budget 3600

#./smartbugs -t slither -f samples/Split1/* --time-budget 7200