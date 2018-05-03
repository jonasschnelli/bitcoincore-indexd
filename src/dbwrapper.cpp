// Copyright (c) 2012-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <dbwrapper.h>

#include <utils.h>

#include <memory>

#include <leveldb/cache.h>
#include <leveldb/env.h>
#include <leveldb/filter_policy.h>
#include <memenv.h>
#include <stdint.h>
#include <algorithm>

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
    log_print("LevelDB using max_open_files=%d (default=%d)\n",
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
            log_print("Wiping LevelDB in %s\n", path.c_str());
            leveldb::Status result = leveldb::DestroyDB(path, options);
            dbwrapper_private::HandleError(result);
        }
        //TryCreateDirectories(path);
        log_print("Opening LevelDB in %s\n", path.c_str());
    }
    leveldb::Status status = leveldb::DB::Open(options, path, &pdb);
    dbwrapper_private::HandleError(status);
    log_print("Opened LevelDB successfully\n");

    /*if (gArgs.GetBoolArg("-forcecompactdb", false)) {
        log_print("Starting database compaction of %s\n", path.c_str();
        pdb->CompactRange(nullptr, nullptr);
        log_print("Finished database compaction of %s\n", path.c_str()));
    }*/

    // The base-case obfuscation key, which is a noop.
    obfuscate_key = std::vector<unsigned char>(OBFUSCATE_KEY_NUM_BYTES, '\000');

    bool key_exists = Read(OBFUSCATE_KEY_KEY, obfuscate_key);

    if (!key_exists && obfuscate && IsEmpty()) {
        // Initialize non-degenerate obfuscation if it won't upset
        // existing, non-obfuscated data.
        std::vector<unsigned char> new_key = CreateObfuscateKey();

        // Write `new_key` so we don't obfuscate the key with itself
        Write(OBFUSCATE_KEY_KEY, new_key);
        obfuscate_key = new_key;

        log_print("Wrote new obfuscate key for %s\n", path.c_str());
    }

    log_print("Using obfuscation key for %s\n", path.c_str());
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
        log_print("WriteBatch memory usage: db=%s, before=%.1fMiB, after=%.1fMiB\n",
                 m_name.c_str(), mem_before, mem_after);
    }
    return true;
}

size_t CDBWrapper::DynamicMemoryUsage() const {
    std::string memory;
    if (!pdb->GetProperty("leveldb.approximate-memory-usage", &memory)) {
        log_print("Failed to get approximate-memory-usage property\n");
        return 0;
    }
    return stoul(memory);
}

// Prefixed with null character to avoid collisions with other keys
//
// We must use a string constructor which specifies length so that we copy
// past the null-terminator.
const std::string CDBWrapper::OBFUSCATE_KEY_KEY("\000obfuscate_key", 14);

const unsigned int CDBWrapper::OBFUSCATE_KEY_NUM_BYTES = 8;

/**
 * Returns a string (consisting of 8 random bytes) suitable for use as an
 * obfuscating XOR key.
 */
std::vector<unsigned char> CDBWrapper::CreateObfuscateKey() const
{
    unsigned char buff[OBFUSCATE_KEY_NUM_BYTES];
    //GetRandBytes(buff, OBFUSCATE_KEY_NUM_BYTES);
    return std::vector<unsigned char>(&buff[0], &buff[OBFUSCATE_KEY_NUM_BYTES]);

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
    log_print("%s\n", errmsg.c_str());
    throw dbwrapper_error(errmsg);
}

const std::vector<unsigned char>& GetObfuscateKey(const CDBWrapper &w)
{
    return w.obfuscate_key;
}

} // namespace dbwrapper_private

DatabaseLEVELDB::DatabaseLEVELDB() : db("/tmp/dummyleveldb", 300*1024*1024, false, false, true) {

}

bool DatabaseLEVELDB::put(const uint8_t* key, unsigned int key_len, const uint8_t* value, unsigned int value_len) {
    cache[std::vector<uint8_t>(key, key+key_len)] = std::vector<uint8_t>(value, value + value_len);
    if (cache.size() == 100000) {
        CDBBatch batch(db);
        for (auto const& it : cache) {
            batch.Write(it.first, it.second);
        }
        db.WriteBatch(batch);
        batch.Clear();
        cache.clear();
    }
}


bool DatabaseLEVELDB::open(const std::string& path) {
    return true;
}


bool DatabaseLEVELDB::close() {
    return true;
}

bool DatabaseLEVELDB::beginTXN() {
    return true;
}

bool DatabaseLEVELDB::commitTXN() {
    return true;
}


