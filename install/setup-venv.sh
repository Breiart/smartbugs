#!/bin/bash

# tested for python >= 3.6.9
# python < 3.10 will give an error when using the ':'-feature in input patterns
python3 -m venv venv
source venv/bin/activate

# avoid spurious errors/warnings; the next two lines could be omitted
pip install --upgrade pip
pip install wheel 

pip install pygments

# install the packages needed by smartbugs
pip install pyyaml colorama requests semantic_version docker py-cpuinfo

# install packages needed for the HTML report generator
SB_DIR="$(cd "$(dirname "$0")/.." && pwd)"
pip install -r "$SB_DIR/generate_report/requirements.txt"