// Copyright (c) 2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <db_leveldb.h>

#include <hash.h>
#include <utils.h>

#include <assert.h>
#include <memory>

#include <leveldb/cache.h>
#include <leveldb/env.h>
#include <leveldb/filter_policy.h>
#include <memenv.h>
#include <stdint.h>
#include <algorithm>

#include <btc/buffer.h>
#include <btc/serialize.h>

const static char DB_BLOCKMAP = 'B';
const static char DB_TXINDEX  = 'T';
class CBitcoinLevelDBLogger : public leveldb::Logger {
public:
    // This code is adapted from posix_logger.h, which is why it is using vsprintf.
    // Please do not do this in normal code
    void Logv(const char * format, va_list ap) override {

    }
};

static void SetMaxOpenFiles(leveldb::Options *options) {
    // On most platforms the default setting of max_open_files (which is 1000)
    // is optimal. On Windows using a large file count is OK because the handles
    // do not interfere with select() loops. On 64-bit Unix hosts this value is
    // also OK, because up to that amount LevelDB will use an mmap
    // implementation that does not use extra file descriptors (the fds are
    // closed after being mmaped).
    //
    // Increasing the value beyond the default is dangerous because LevelDB will
    // fall back to a non-mmap implementation when the file count is too large.
    // On 32-bit Unix host we should decrease the value because the handles use
    // up real fds, and we want to avoid fd exhaustion issues.
    //
    // See PR #12495 for further discussion.

    int default_open_files = options->max_open_files;
#ifndef WIN32
    if (sizeof(void*) < 8) {
        options->max_open_files = 64;
    }
#endif
    LogPrintf("LevelDB using max_open_files=%d (default=%d)\n",
             options->max_open_files, default_open_files);
}

static leveldb::Options GetOptions(size_t nCacheSize)
{
    leveldb::Options options;
    options.block_cache = leveldb::NewLRUCache(nCacheSize / 2);
    options.write_buffer_size = nCacheSize / 4; // up to two write buffers may be held in memory simultaneously
    options.filter_policy = leveldb::NewBloomFilterPolicy(10);
    options.compression = leveldb::kNoCompression;
    options.info_log = new CBitcoinLevelDBLogger();
    if (leveldb::kMajorVersion > 1 || (leveldb::kMajorVersion == 1 && leveldb::kMinorVersion >= 16)) {
        // LevelDB versions before 1.16 consider short writes to be corruption. Only trigger error
        // on corruption in later versions.
        options.paranoid_checks = true;
    }
    SetMaxOpenFiles(&options);
    return options;
}

CDBWrapper::CDBWrapper(const std::string& path, size_t nCacheSize, bool fMemory, bool fWipe, bool obfuscate)
    : m_name(path)
{
    penv = nullptr;
    readoptions.verify_checksums = true;
    iteroptions.verify_checksums = true;
    iteroptions.fill_cache = false;
    syncoptions.sync = true;
    options = GetOptions(nCacheSize);
    options.create_if_missing = true;
    if (fMemory) {
        penv = leveldb::NewMemEnv(leveldb::Env::Default());
        options.env = penv;
    } else {
        if (fWipe) {
            LogPrintf("Wiping LevelDB in %s\n", path.c_str());
            leveldb::Status result = leveldb::DestroyDB(path, options);
            dbwrapper_private::HandleError(result);
        }
        //TryCreateDirectories(path);
        LogPrintf("Opening LevelDB in %s\n", path.c_str());
    }
    leveldb::Status status = leveldb::DB::Open(options, path, &pdb);
    dbwrapper_private::HandleError(status);
    LogPrintf("Opened LevelDB successfully\n");

    /*if (gArgs.GetBoolArg("-forcecompactdb", false)) {
        LogPrintf("Starting database compaction of %s\n", path.c_str();
        pdb->CompactRange(nullptr, nullptr);
        LogPrintf("Finished database compaction of %s\n", path.c_str()));
    }*/
}

CDBWrapper::~CDBWrapper()
{
    delete pdb;
    pdb = nullptr;
    delete options.filter_policy;
    options.filter_policy = nullptr;
    delete options.info_log;
    options.info_log = nullptr;
    delete options.block_cache;
    options.block_cache = nullptr;
    delete penv;
    options.env = nullptr;
}

bool CDBWrapper::WriteBatch(CDBBatch& batch, bool fSync)
{
    const bool log_memory = true;
    double mem_before = 0;
    if (log_memory) {
        mem_before = DynamicMemoryUsage() / 1024.0 / 1024;
    }
    leveldb::Status status = pdb->Write(fSync ? syncoptions : writeoptions, &batch.batch);
    dbwrapper_private::HandleError(status);
    if (log_memory) {
        double mem_after = DynamicMemoryUsage() / 1024.0 / 1024;
        LogPrintf("WriteBatch memory usage: db=%s, before=%.1fMiB, after=%.1fMiB\n",
                 m_name.c_str(), mem_before, mem_after);
    }
    return true;
}

size_t CDBWrapper::DynamicMemoryUsage() const {
    std::string memory;
    if (!pdb->GetProperty("leveldb.approximate-memory-usage", &memory)) {
        LogPrintf("Failed to get approximate-memory-usage property\n");
        return 0;
    }
    return stoul(memory);
}

bool CDBWrapper::IsEmpty()
{
    std::unique_ptr<CDBIterator> it(NewIterator());
    it->SeekToFirst();
    return !(it->Valid());
}

CDBIterator::~CDBIterator() { delete piter; }
bool CDBIterator::Valid() const { return piter->Valid(); }
void CDBIterator::SeekToFirst() { piter->SeekToFirst(); }
void CDBIterator::Next() { piter->Next(); }

namespace dbwrapper_private {

void HandleError(const leveldb::Status& status)
{
    if (status.ok())
        return;
    const std::string errmsg = "Fatal LevelDB error: " + status.ToString();
    LogPrintf("%s\n", errmsg.c_str());
    throw dbwrapper_error(errmsg);
}

} // namespace dbwrapper_private

DatabaseLEVELDB::DatabaseLEVELDB(const std::string& path) : db(path, 300*1024*1024, false, false, true) {

    if (g_args.GetBoolArg("-dumpdb", false)) {
        std::unique_ptr<CDBIterator> pcursor(db.NewIterator());
        std::vector<uint8_t> v_key;
        pcursor->SeekToFirst();
        unsigned int cnt = 0;
        while (pcursor->Valid()) {
            std::vector<uint8_t> v_key;
            std::vector<uint8_t> v_value;
            if (pcursor->GetKey(v_key)) {
                pcursor->GetValue(v_value);
                if (v_key[0] == DB_BLOCKMAP) {
                    struct const_buffer buf = {&v_key[1], 4};
                    unsigned int blockmap_key = 0;
                    deser_u32(&blockmap_key, &buf);
                    LogPrintf("Blockmap %s to %d\n", HexStrRev(v_value), blockmap_key);
                }
                else if (v_key[0] == DB_TXINDEX) {
                    struct const_buffer buf = {&v_value[0], 4};
                    unsigned int blockmap_key = 0;
                    deser_u32(&blockmap_key, &buf);
                    v_key.erase(v_key.begin());
                    LogPrintf("TX index %s to %d\n", HexStrRev(v_key), blockmap_key);
                }
                pcursor->Next();
            }
            else {
                break;
            }
            cnt++;
        }
        exit(1);
    }
}

bool DatabaseLEVELDB::loadBlockMap(std::map<unsigned int, Hash256>& blockhash_map, std::map<Hash256, unsigned int>& blockhash_map_rev, unsigned int &counter) {
    std::unique_ptr<CDBIterator> pcursor(db.NewIterator());
    std::vector<uint8_t> v_key;
    v_key.push_back(DB_BLOCKMAP);
    pcursor->Seek(v_key);
    while (pcursor->Valid()) {
        std::vector<uint8_t> v_key;
        std::vector<uint8_t> v_value;
        if (pcursor->GetKey(v_key) && v_key[0] == DB_BLOCKMAP) {
            struct const_buffer buf = {&v_key[1], 4};
            unsigned int blockmap_key = 0;
            deser_u32(&blockmap_key, &buf);
            if (blockmap_key > counter) counter = blockmap_key;
            pcursor->GetValue(v_value);

            blockhash_map[blockmap_key] = Hash256(&v_value[0]);
            blockhash_map_rev[Hash256(&v_value[0])] = blockmap_key; //TODO: don't waste memory by holding the hash twice in mem

            pcursor->Next();
        }
        else {
            break;
        }
    }
    return true;
}

bool DatabaseLEVELDB::putTxIndex(const uint8_t* key, unsigned int key_len, const uint8_t* value, unsigned int value_len, bool avoid_flush) {
    std::vector<uint8_t> v_key(key, key+key_len);
    v_key.insert(v_key.begin(), DB_TXINDEX);
    cache[v_key] = std::vector<uint8_t>(value, value + value_len);
    return true;
}

bool DatabaseLEVELDB::putBlockMap(const uint8_t* key, unsigned int key_len, const uint8_t* value, unsigned int value_len) {
    std::vector<uint8_t> v_key(key, key+key_len);
    v_key.insert(v_key.begin(), DB_BLOCKMAP);
    cache[v_key] = std::vector<uint8_t>(value, value + value_len);

    // write the batch when we have reached the desired cache size
    if (cache.size() >= 100000) {
        CDBBatch batch(db);
        for (auto const& it : cache) {
            batch.Write(it.first, it.second);
        }
        db.WriteBatch(batch);
        batch.Clear();
        cache.clear();
    }
    return true;
}

bool DatabaseLEVELDB::lookupTXID(const uint8_t* key, unsigned int key_len, Hash256& blockhash) {
    std::vector<uint8_t> v_key(key, key+key_len);
    std::vector<uint8_t> v_value;
    v_key.insert(v_key.begin(), DB_TXINDEX);
    if (db.Read(v_key, v_value)) {
        assert(v_value.size() == 4);
        v_value.insert(v_value.begin(), DB_BLOCKMAP);
        std::vector<uint8_t> v_value_hash;
        if (db.Read(v_value, v_value_hash)) {
            assert(v_value_hash.size() == 32);
            blockhash = Hash256(&v_value_hash[0]);
            return true;
        }
    }
    return false;
}

bool DatabaseLEVELDB::close() {
    return true;
}
