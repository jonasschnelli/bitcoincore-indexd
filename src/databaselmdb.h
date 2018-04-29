#ifndef DATABASELMDB_H
#define DATABASELMDB_H

#include <dbinterface.h>
#include <lmdb.h>

class DatabaseLMDB : public IndexDatabaseInterface
{
private:
    MDB_env *m_env;
    MDB_dbi m_dbi;
    MDB_txn *m_txn;
    MDB_cursor *cursor;

public:
    DatabaseLMDB();

    bool open(const std::string& path);
    bool beginTXN();
    bool put(const uint8_t* key, unsigned int key_len, const uint8_t* value, unsigned int value_len);
    bool commitTXN();
    bool close();
};

#endif // DATABASELMDB_H
