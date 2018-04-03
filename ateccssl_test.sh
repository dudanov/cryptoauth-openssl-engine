#!/bin/bash

set -e

# Very simple engine test with current OpenSSL version installed

info() {
    echo ">>> $@" >&2
}

die() {
    echo "EEE: $@" >&2
    exit 1
}

ATECC_KEY=${ATECC_KEY:-"ATECCx08:00:09:c0:01"}
ATECC_KEY_ROOT=${ATECC_KEY:-"ATECCx08:00:09:c0:02"}
OPENSSL=${OPENSSL:-"openssl"}

OPENSSL_NEW_API=0

# Check local OpenSSL version
if openssl version | grep '1\.1\.' > /dev/null; then
    OPENSSL_NEW_API=1
    info "Using OpenSSL 1.1.x API"
elif openssl version | grep '1\.0\.2' > /dev/null; then
    OPENSSL_NEW_API=0
    info "Using OpenSSL 1.0.2 API"
else
    die "Uncompatible OpenSSL version, must be 1.1.x or 1.0.2"
fi


cp_backup() {
    local SRC=$1
    local DST=$2
    local SUDO=$3

    if [[ -e $DST ]]; then
        info "backing up $DST..."
        $SUDO cp $DST $DST.backup
    fi

    info "copying $SRC to $DST..."
    $SUDO cp $SRC $DST
}

# build library
info "Building engine..."
make TARGET_HAL=I2C libateccssl -j4


# test 0: engine load
info "Test engine loading..."
{
    echo "engine dynamic -pre SO_PATH:`readlink -f .build/libateccssl.so` -pre LIST_ADD:1 -pre ID:ateccx08 -pre LOAD"
} | openssl | grep 'Failure' && {
    die "-> Failed"
} || {
    info "-> Passed"
}

# test 1: sign file
info "Test file signing..."

FILE_TO_SIGN=$0

{
    openssl dgst -engine .build/libateccssl.so -keyform ENGINE -sha256 -sign $ATECC_KEY -out $FILE_TO_SIGN.sign $FILE_TO_SIGN &&
    openssl dgst -engine .build/libateccssl.so -keyform ENGINE -sha256 -verify $ATECC_KEY -signature $FILE_TO_SIGN.sign $FILE_TO_SIGN
} && {
    rm -f $FILE_TO_SIGN.sign
    info "-> Passed"
} || {
    rm -f $FILE_TO_SIGN.sign
    die "-> Failed"
}


# test 2: create CSR and sign it here

info "Test CSR request signing..."

ROOT_FILE=root.crt.pem
CSR_FILE=test.csr.pem
CRT_FILE=test.crt.pem

{
    # make root certificate
    echo -ne "\n\n\n\n\n\n\n" | openssl req -engine .build/libateccssl.so -keyform ENGINE -x509 -new -key $ATECC_KEY_ROOT -days 10000 -out $ROOT_FILE &&
    echo -ne "\n\n\n\n\n\ntest\n\n\n" | openssl req -engine .build/libateccssl.so -keyform ENGINE -new -key $ATECC_KEY -out $CSR_FILE &&
    openssl x509 -engine .build/libateccssl.so -CAkeyform ENGINE -req -in $CSR_FILE -CA $ROOT_FILE -CAkey $ATECC_KEY_ROOT -CAcreateserial -out $CRT_FILE -days 5000 &&
    openssl verify -verbose -CAfile $ROOT_FILE $CRT_FILE
} && {
    rm -f $CSR_FILE $ROOT_FILE $CRT_FILE
    info "-> Passed"
} || {
    # rm -f $CSR_FILE $ROOT_FILE $CRT_FILE
    die "-> Failed"
}

info "All tests are passed!"
