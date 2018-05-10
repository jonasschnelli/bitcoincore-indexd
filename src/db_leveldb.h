// Copyright (c) 2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOINCORE_INDEXD_DB_LEVELDB_H
#define BITCOINCORE_INDEXD_DB_LEVELDB_H

#include <vector>
#include <map>

#include <dbinterface.h>

#include <leveldb/db.h>
#include <leveldb/write_batch.h>

//static const size_t DBWRAPPER_PREALLOC_KEY_SIZE = 64;
//static const size_t DBWRAPPER_PREALLOC_VALUE_SIZE = 1024;

class dbwrapper_error : public std::runtime_error
{
public:
    explicit dbwrapper_error(const std::string& msg) : std::runtime_error(msg) {}
};

class CDBWrapper;

/** These should be considered an implementation detail of the specific database.
 */
namespace dbwrapper_private {

/** Handle database error by throwing dbwrapper_error exception.
 */
void HandleError(const leveldb::Status& status);

/** Work around circular dependency, as well as for testing in dbwrapper_tests.
 * Database obfuscation should be considered an implementation detail of the
 * specific database.
 */
const std::vector<unsigned char>& GetObfuscateKey(const CDBWrapper &w);

};

/** Batch of changes queued to be written to a CDBWrapper */
class CDBBatch
{
    friend class CDBWrapper;

private:
    const CDBWrapper &parent;
    leveldb::WriteBatch batch;

    size_t size_estimate;

public:
    /**
     * @param[in] _parent   CDBWrapper that this batch is to be submitted to
     */
    explicit CDBBatch(const CDBWrapper &_parent) : parent(_parent), size_estimate(0) { };

    void Clear()
    {
        batch.Clear();
        size_estimate = 0;
    }

    template <typename K, typename V>
    void Write(const K& key, const V& value)
    {
        leveldb::Slice slKey((const char *)key.data(), key.size());
        leveldb::Slice slValue((const char *)value.data(), value.size());
        batch.Put(slKey, slValue);
        size_estimate += 3 + (slKey.size() > 127) + slKey.size() + (slValue.size() > 127) + slValue.size();
    }

    template <typename K>
    void Erase(const K& key)
    {
        /*ssKey.reserve(DBWRAPPER_PREALLOC_KEY_SIZE);
        ssKey << key;
        leveldb::Slice slKey(ssKey.data(), ssKey.size());

        batch.Delete(slKey);
        // LevelDB serializes erases as:
        // - byte: header
        // - varint: key length
        // - byte[]: key
        // The formula below assumes the key is less than 16kB.
        size_estimate += 2 + (slKey.size() > 127) + slKey.size();
        ssKey.clear();*/
    }

    size_t SizeEstimate() const { return size_estimate; }
};

class CDBIterator
{
private:
    const CDBWrapper &parent;
    leveldb::Iterator *piter;

public:

    /**
     * @param[in] _parent          Parent CDBWrapper instance.
     * @param[in] _piter           The original leveldb iterator.
     */
    CDBIterator(const CDBWrapper &_parent, leveldb::Iterator *_piter) :
        parent(_parent), piter(_piter) { };
    ~CDBIterator();

    bool Valid() const;

    void SeekToFirst();

    template<typename K> void Seek(const K& key) {
        leveldb::Slice slKey((const char *)key.data(), key.size());
        piter->Seek(slKey);
    }

    void Next();

    template<typename K> bool GetKey(K& key) {
        leveldb::Slice slKey = piter->key();
        key.assign(slKey.data(), slKey.data() + slKey.size());
        return true;
    }

    template<typename V> bool GetValue(V& value) {
        leveldb::Slice slValue = piter->value();
        try {
            value.assign(slValue.data(), slValue.data() + slValue.size());
        } catch (const std::exception&) {
            return false;
        }
        return true;
    }

    unsigned int GetValueSize() {
        return piter->value().size();
    }

};

class CDBWrapper
{
    friend const std::vector<unsigned char>& dbwrapper_private::GetObfuscateKey(const CDBWrapper &w);
private:
    //! custom environment this database is using (may be nullptr in case of default environment)
    leveldb::Env* penv;

    //! database options used
    leveldb::Options options;

    //! options used when reading from the database
    leveldb::ReadOptions readoptions;

    //! options used when iterating over values of the database
    leveldb::ReadOptions iteroptions;

    //! options used when writing to the database
    leveldb::WriteOptions writeoptions;

    //! options used when sync writing to the database
    leveldb::WriteOptions syncoptions;

    //! the database itself
    leveldb::DB* pdb;

    //! the name of this database
    std::string m_name;

public:
    /**
     * @param[in] path        Location in the filesystem where leveldb data will be stored.
     * @param[in] nCacheSize  Configures various leveldb cache settings.
     * @param[in] fMemory     If true, use leveldb's memory environment.
     * @param[in] fWipe       If true, remove all existing data.
     * @param[in] obfuscate   If true, store data obfuscated via simple XOR. If false, XOR
     *                        with a zero'd byte array.
     */
    CDBWrapper(const std::string& path, size_t nCacheSize, bool fMemory = false, bool fWipe = false, bool obfuscate = false);
    ~CDBWrapper();

    template <typename K, typename V>
    bool Read(const K& key, V& value) const
    {
        leveldb::Slice slKey((const char *)key.data(), key.size());
        std::string strValue;
        leveldb::Status status = pdb->Get(readoptions, slKey, &strValue);
        if (!status.ok()) {
            if (status.IsNotFound())
                return false;
            LogPrintf("LevelDB read failure: %s\n", status.ToString());
            dbwrapper_private::HandleError(status);
        }
        try {
            value.assign(strValue.data(), strValue.data() + strValue.size());
        } catch (const std::exception&) {
            return false;
        }
        return true;
    }

    template <typename K, typename V>
    bool Write(const K& key, const V& value, bool fSync = false)
    {
        CDBBatch batch(*this);
        batch.Write(key, value);
        return WriteBatch(batch, fSync);
    }

    template <typename K>
    bool Exists(const K& key) const
    {
        leveldb::Slice slKey((const char *)key.data(), key.size());
        std::string strValue;
        leveldb::Status status = pdb->Get(readoptions, slKey, &strValue);

        if (!status.ok()) {
            if (status.IsNotFound())
                return false;
            LogPrintf("LevelDB read failure: %s\n", status.ToString());
            dbwrapper_private::HandleError(status);
        }
        return true;
    }

    template <typename K>
    bool Erase(const K& key, bool fSync = false)
    {
        CDBBatch batch(*this);
        batch.Erase(key);
        return WriteBatch(batch, fSync);
    }

    bool WriteBatch(CDBBatch& batch, bool fSync = false);

    // Get an estimate of LevelDB memory usage (in bytes).
    size_t DynamicMemoryUsage() const;

    // not available for LevelDB; provide for compatibility with BDB
    bool Flush()
    {
        return true;
    }

    bool Sync()
    {
        CDBBatch batch(*this);
        return WriteBatch(batch, true);
    }

    CDBIterator *NewIterator()
    {
        return new CDBIterator(*this, pdb->NewIterator(iteroptions));
    }

    /**
     * Return true if the database managed by this class contains no entries.
     */
    bool IsEmpty();

    /**
     * Compact a certain range of keys in the database.
     */
    template<typename K>
    void CompactRange(const K& key_begin, const K& key_end) const
    {
        /*CDataStream ssKey1(SER_DISK, CLIENT_VERSION), ssKey2(SER_DISK, CLIENT_VERSION);
        ssKey1.reserve(DBWRAPPER_PREALLOC_KEY_SIZE);
        ssKey2.reserve(DBWRAPPER_PREALLOC_KEY_SIZE);
        ssKey1 << key_begin;
        ssKey2 << key_end;
        leveldb::Slice slKey1(ssKey1.data(), ssKey1.size());
        leveldb::Slice slKey2(ssKey2.data(), ssKey2.size());
        pdb->CompactRange(&slKey1, &slKey2);
        */
    }

};



class DatabaseLEVELDB : public IndexDatabaseInterface
{
private:
    size_t m_size_estimate = 0; //keeps track of the size of the unflushed cached
    std::map<std::vector<uint8_t>, std::vector<uint8_t>> cache;
    CDBWrapper db;
public:
    DatabaseLEVELDB(const std::string& path);

    bool flush(bool force = false);
    bool open(const std::string& path);
    bool loadBlockMap(std::map<unsigned int, Hash256>& blockhash_map, std::map<Hash256, unsigned int>& blockhash_map_rev, unsigned int &counter);
    bool putTxIndex(const uint8_t* key, unsigned int key_len, const uint8_t* value, unsigned int value_len, bool avoid_flush);
    bool putBlockMap(const uint8_t* key, unsigned int key_len, const uint8_t* value, unsigned int value_len);
    bool lookupTXID(const uint8_t* key, unsigned int key_len, Hash256& blockhash);
    bool close();
};

#endif // BITCOINCORE_INDEXD_DB_LEVELDB_H
