#!/usr/bin/env bash

set -eux

apt update
apt install python3-pip cmake ninja-build libpcap-dev unzip -y

# Install morden json parser for C++
if [ ! -f "json.hpp" ]; then
    wget https://github.com/nlohmann/json/releases/download/v3.10.5/json.hpp
fi

# Install mlpack (Note that, mlpack repo. is stable.)
apt install libmlpack-dev mlpack-bin libarmadillo-dev -y

# Install GFlags
apt install libgflags-dev -y

# Install other python libraries
pip3 install matplotlib scikit-learn

chmod +x install-z3.sh
./install-z3.sh
chmod +x install-pcap.sh
./install-pcap.sh
