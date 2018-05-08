// Copyright (c) 2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOINCORE_INDEXD_DBINTERFACE_H
#define BITCOINCORE_INDEXD_DBINTERFACE_H

#include <stdint.h>
#include <string>
#include <vector>


//! Interface for the database
class IndexDatabaseInterface
{
public:
    virtual ~IndexDatabaseInterface() {}

    virtual bool close() = 0;
    virtual bool put_txindex(const uint8_t* key, unsigned int key_len, const uint8_t* value, unsigned int value_len) = 0;
    virtual bool put_header(const uint8_t* key, unsigned int key_len, const uint8_t* value, unsigned int value_len) = 0;
};

#endif // BITCOINCORE_INDEXD_DBINTERFACE_H
