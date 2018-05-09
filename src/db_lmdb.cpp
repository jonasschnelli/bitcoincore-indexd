// Copyright (c) 2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "db_lmdb.h"

#include <utils.h>

DatabaseLMDB::DatabaseLMDB(const std::string& path) {
    int rc = 0;
    rc = mdb_env_create(&m_env);
    rc = mdb_env_set_mapsize(m_env, 21474836480); //20GB
    rc = mdb_env_open(m_env, path.c_str(), MDB_NOSYNC | MDB_NOSUBDIR, 0664);
    rc = mdb_txn_begin(m_env, NULL, 0, &m_txn);
    rc = mdb_open(m_txn, NULL, 0, &m_dbi);
    mdb_txn_abort(m_txn);
}

bool DatabaseLMDB::loadBlockMap(std::map<unsigned int, Hash256>& blockhash_map, unsigned int &counter) {

}

bool DatabaseLMDB::beginTXN() {
    int rc = mdb_txn_begin(m_env, NULL, 0, &m_txn);
    return true;
}

bool DatabaseLMDB::putTxIndex(const uint8_t* key_in, unsigned int key_len, const uint8_t* value, unsigned int value_len, bool avoid_flush) {
    MDB_val key, data, data_r;
    key.mv_size = key_len;
    key.mv_data = (void *)key_in;
    data.mv_size = value_len;
    data.mv_data = (void *)value;

    if (m_txnsize == 0) {
        beginTXN();
    }

//    std::vector<uint8_t> hex_k(std::reverse_iterator<uint8_t*>((uint8_t*)key.mv_data + key.mv_size), std::reverse_iterator<uint8_t*>((uint8_t*)key.mv_data));

//    MDB_txn *txn_r;
//    int rc = mdb_txn_begin(m_env, NULL, MDB_RDONLY, &txn_r);
//    rc = mdb_get(txn_r, m_dbi, &key, &data_r);
//    if (rc == 0) {
//        std::vector<uint8_t> hex_v(std::reverse_iterator<uint8_t*>((uint8_t*)data_r.mv_data + data_r.mv_size), std::reverse_iterator<uint8_t*>((uint8_t*)data_r.mv_data));
//        printf("key: %s, data: %s\n", HexStr(hex_k).c_str(), HexStr(hex_v).c_str());
//    }
//    mdb_txn_abort(txn_r);

//    printf("write-key: %s\n", HexStr(hex_k).c_str());
    int rc = mdb_put(m_txn, m_dbi, &key, &data, 0);
    if(rc) {
        printf("ERROR PUT %d\n", rc);
        return false;
    }
    if (++m_txnsize == 10000) {
        commitTXN();
        m_txnsize = 0;
    }
    return true;
}

bool DatabaseLMDB::putBlockMap(const uint8_t* key, unsigned int key_len, const uint8_t* value, unsigned int value_len) {
    return true;
}

bool DatabaseLMDB::commitTXN() {
    int rc = mdb_txn_commit(m_txn);
    if (rc) {
        printf("ERROR COMMIT %d!\n", rc);
        struct MDB_envinfo current_info;
        mdb_env_info(m_env, &current_info);
        printf("---> %lu\n", current_info.me_mapsize);
        return false;
    }
    mdb_env_sync(m_env, 1);
    return true;
}


bool DatabaseLMDB::close() {
    mdb_close(m_env, m_dbi);
    mdb_env_close(m_env);
    return true;
}
