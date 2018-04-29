#ifndef BTCNODE_H
#define BTCNODE_H

#include <vector>
#include <map>
#include <string.h>

#include <utils.h>

#include <dbinterface.h>

class Hash256 {
public:
    uint8_t m_data[32];
    Hash256(uint8_t *t) {
        memcpy(m_data, t, 32);
    }
    inline std::string GetHex() const
    {
        return HexStr(std::reverse_iterator<const uint8_t*>(m_data + sizeof(m_data)), std::reverse_iterator<const uint8_t*>(m_data));
    }
    inline int Compare(const Hash256& other) const { return memcmp(m_data, other.m_data, sizeof(m_data)); }
    friend inline bool operator==(const Hash256& a, const Hash256& b) { return a.Compare(b) == 0; }
    friend inline bool operator!=(const Hash256& a, const Hash256& b) { return a.Compare(b) != 0; }
    friend inline bool operator<(const Hash256& a, const Hash256& b) { return a.Compare(b) < 0; }
};

class HeaderEntry {
public:
    const Hash256 m_hash;
    uint8_t m_flags;
    unsigned int m_height;
    HeaderEntry(uint8_t *t, unsigned int height) : m_hash(Hash256(t)), m_flags(0), m_height(height) {}
    void setRequested() {
        m_flags = 1;
    }
    bool isRequested() const {
        return (m_flags > 0);
    }
    void setLoaded() {
        m_flags = 2;
    }
};

class BTCNodePriv;

class BTCNode
{
public:
    int m_txnsize;
    IndexDatabaseInterface *db;
    HeaderEntry* bestblock;
    std::map<Hash256, HeaderEntry*> m_blocks_in_flight;
    std::map<Hash256, HeaderEntry*> m_blocks;
    int processed_up_to_height;
    std::vector<HeaderEntry*> m_headers;

    BTCNode(IndexDatabaseInterface *db_in);
    void SyncHeaders();
    void SyncBlocks();
    bool AddHeader(uint8_t* t, uint8_t* prevhash) {
        if (m_headers.size() > 0 && m_headers.back()->m_hash != prevhash) {
            log_print("Failed to connect header");
            return false;
        }
        HeaderEntry *hEntry = new HeaderEntry(t, m_headers.size());
        m_headers.push_back(hEntry);
        m_blocks[m_headers.back()->m_hash] = hEntry;
        return true;
    }
    unsigned int GetHeight() {
        return m_headers.size();
    }
    const uint8_t * GetRawBestBlockHash() {
        return m_headers.back()->m_hash.m_data;
    }
    void processTXID(const Hash256& block, const Hash256& tx) {
        if (m_txnsize == 0) {
            db->beginTXN();
        }
        //uint64_t s = GetTimeMillis();
        db->put(tx.m_data, 32, block.m_data, 32);
        //printf("PUT %lld\n", GetTimeMillis()-s);
        if (++m_txnsize == 10000) {
            uint64_t s = GetTimeMillis();
            db->commitTXN();
            printf("Commit DB TXN %lld\n", GetTimeMillis()-s);
            m_txnsize = 0;
        }
    }
    BTCNodePriv *priv;
};

#endif // BTCNODE_H
