#!/usr/bin/env bash

set -eux

DOWNLOAD_URL="https://github.com/Z3Prover/z3/archive/refs/tags/z3-4.11.0.zip"
DOWNLOAD_FILENAME=${DOWNLOAD_URL##*/}
UNZIP_DIR_NAME="z3-${DOWNLOAD_FILENAME%*.zip}"
DIR_NAME="z3"

if [ -f ${DOWNLOAD_FILENAME} ]; then
    rm ${DOWNLOAD_FILENAME}
fi
if [ -d ${UNZIP_DIR_NAME} ]; then
    rm -r ${}
fi
if [ -d ${DIR_NAME} ]; then
    rm -r ${DIR_NAME}
fi

wget ${DOWNLOAD_URL}
unzip ${DOWNLOAD_FILENAME}
mv ${UNZIP_DIR_NAME} ${DIR_NAME}
cd $_

python3 scripts/mk_make.py
cd build
make -j 64
sudo make install

# back to env
cd ../../

rm ${DOWNLOAD_FILENAME}

echo "Done ${DIR_NAME}."
