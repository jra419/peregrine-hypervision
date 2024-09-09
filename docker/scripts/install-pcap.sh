#!/usr/bin/env bash

set -eux

DOWNLOAD_URL="https://github.com/seladb/PcapPlusPlus/releases/download/v21.11/pcapplusplus-21.11-ubuntu-20.04-gcc-9.tar.gz"
DOWNLOAD_FILENAME=${DOWNLOAD_URL##*/}
UNTAR_DIR_NAME=${DOWNLOAD_FILENAME%*.tar.gz}
DIR_NAME="pcapplusplus"

if [ -f ${DOWNLOAD_FILENAME} ]; then
    rm ${DOWNLOAD_FILENAME}
fi
if [ -d ${UNTAR_DIR_NAME} ]; then
    rm -r ${UNTAR_DIR_NAME}
fi
if [ -d ${DIR_NAME} ]; then
    rm -r ${DIR_NAME}
fi

wget ${DOWNLOAD_URL}
tar -zxf ${DOWNLOAD_FILENAME}
mv ${UNTAR_DIR_NAME} ${DIR_NAME}
cd $_
./install.sh

# back to env
cd ../

rm ${DOWNLOAD_FILENAME}

echo "Done Libpcap++."
