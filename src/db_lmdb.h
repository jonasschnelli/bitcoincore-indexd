// Copyright (c) 2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOINCORE_INDEXD_DB_LMDB_H
#define BITCOINCORE_INDEXD_DB_LMDB_H

#include <dbinterface.h>
#include <lmdb.h>

class DatabaseLMDB : public IndexDatabaseInterface
{
private:
    MDB_env *m_env;
    MDB_dbi m_dbi;
    MDB_txn *m_txn;
    MDB_cursor *cursor;

    int m_txnsize = 0;
    bool beginTXN();
    bool commitTXN();

public:
    DatabaseLMDB(const std::string& path);
    bool loadBlockMap(std::map<unsigned int, Hash256>& blockhash_map, std::map<Hash256, unsigned int>& blockhash_map_rev, unsigned int &counter);
    bool putTxIndex(const uint8_t* key, unsigned int key_len, const uint8_t* value, unsigned int value_len, bool avoid_flush);
    bool putBlockMap(const uint8_t* key, unsigned int key_len, const uint8_t* value, unsigned int value_len);
    bool close();
};

#endif // BITCOINCORE_INDEXD_DB_LMDB_H
