#ifndef BITCOINCORE_INDEXD_BTCNODE_H
#define BITCOINCORE_INDEXD_BTCNODE_H

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
    bool AddHeader(uint8_t* t, uint8_t* prevhash);
    unsigned int GetHeight() { return m_headers.size(); }
    const uint8_t * GetRawBestBlockHash() { return m_headers.back()->m_hash.m_data; }
    void processTXID(const Hash256& block_hash, const Hash256& tx_hash);
    BTCNodePriv *priv;
};

#endif // BITCOINCORE_INDEXD_BTCNODE_H
