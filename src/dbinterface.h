// Copyright (c) 2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOINCORE_INDEXD_DBINTERFACE_H
#define BITCOINCORE_INDEXD_DBINTERFACE_H

#include <stdint.h>
#include <string>
#include <vector>

#include <hash.h>

//! Interface for the database
class IndexDatabaseInterface
{
public:
    virtual ~IndexDatabaseInterface() {}

    virtual bool close() = 0;

    // loads the blockmap table (maps internal-blockhash-key to blockhash)
    virtual bool loadBlockMap(std::map<unsigned int, Hash256>& blockhash_map, std::map<Hash256, unsigned int>& blockhash_map_rev, unsigned int &counter) = 0;
    virtual bool putTxIndex(const uint8_t* key, unsigned int key_len, const uint8_t* value, unsigned int value_len, bool avoid_flush = false) = 0;
    virtual bool putBlockMap(const uint8_t* key, unsigned int key_len, const uint8_t* value, unsigned int value_len) = 0;
};

#endif // BITCOINCORE_INDEXD_DBINTERFACE_H
