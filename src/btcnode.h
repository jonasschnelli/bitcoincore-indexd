#ifndef BITCOINCORE_INDEXD_BTCNODE_H
#define BITCOINCORE_INDEXD_BTCNODE_H

#include <vector>
#include <map>
#include <string.h>

#include <hash.h>
#include <utils.h>

#include <dbinterface.h>


enum BLOCK_STATE {
    BLOCK_STATE_REQUESTED = (1 << 0),
    BLOCK_STATE_INDEXED = (1 << 1),
};

class HeaderEntry {
public:
    const Hash256 m_hash;
    uint8_t m_flags;
    const unsigned int m_primkey; //!< primary key auto-increment, use this for txid->block to save diskspace
    HeaderEntry(uint8_t *t, unsigned int height) : m_hash(Hash256(t)), m_flags(0), m_primkey(height) {}
    void setRequested() {
        m_flags |= BLOCK_STATE_REQUESTED;
    }
    bool isRequested() const {
        return ((m_flags & BLOCK_STATE_REQUESTED) == BLOCK_STATE_REQUESTED);
    }
    void setIndexed() {
        m_flags |= BLOCK_STATE_INDEXED;
    }
    bool isIndexed() {
        return ((m_flags & BLOCK_STATE_INDEXED) == BLOCK_STATE_INDEXED);
    }
};

class BTCNodePriv;

class BTCNode
{
public:
    bool blockflush = false; //lazy mode for DB transactions, make sure we only write complete indexing packages
    IndexDatabaseInterface *db;
    std::map<Hash256, HeaderEntry*> m_blocks_in_flight; //!< map that holds block that are requested
    std::map<Hash256, HeaderEntry*> m_blocks; //!< map that holds all headers //TODO: waste of memory, find a way to only hold the hash once im mem
    std::vector<HeaderEntry*> m_headers;

    std::map<unsigned int, Hash256> m_intcounter_to_hash_map; //<! maps internal blockmap-keys to blockhash
    std::map<Hash256, unsigned int> m_hash_to_intcounter_map; //<! maps blockhash to internal blockmap-key

    unsigned int auto_inc_counter = 0; // the auto incremental blockmap-key index

    BTCNode(IndexDatabaseInterface *db_in);
    ~BTCNode();

    void SyncLoop();
    void Loop();
    bool FetchTX(const Hash256& tx, const Hash256& block, std::vector<unsigned char> &txdata_out);

    bool AddHeader(uint8_t* t, uint8_t* prevhash);
    unsigned int GetHeight() { return m_headers.size(); }
    const uint8_t * GetRawBestBlockHash() { return m_headers.back()->m_hash.m_data; }
    void processTXID(void *key, uint8_t key_len, const Hash256& tx, bool avoid_flush);
    unsigned int addBlockToMap(const Hash256& hash);
    void persistBlockKey(void *block_prim_key, uint8_t block_prim_key_len, const Hash256& blockhash);
    bool isIndexed(const Hash256& hash, unsigned int *block_prim_key = nullptr);
    BTCNodePriv *priv;
};

#endif // BITCOINCORE_INDEXD_BTCNODE_H
