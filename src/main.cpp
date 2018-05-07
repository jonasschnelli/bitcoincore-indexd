// Copyright (c) 2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <time.h>

#include <univalue.h>

#include <lmdb.h>

#include <db_lmdb.h>
#include <db_leveldb.h>
#include <btcnode.h>

static std::string DEFAULT_DB = "leveldb";
int main(int argc, char* argv[])
{
    g_args.ParseParameters(argc, argv);

    IndexDatabaseInterface *db = nullptr;
    if (g_args.GetArg("-database", DEFAULT_DB) == "leveldb") {
        db = new DatabaseLEVELDB(GetDataDir()+"/db_leveldb");
    }
    else if (g_args.GetArg("-database", DEFAULT_DB) == "lmdb") {
        db = new DatabaseLMDB(GetDataDir()+"/db_lmdb");
    }
    else {
        LogPrintf("Database not supported");
        exit(1);
    }
    BTCNode node(db);
    node.SyncHeaders();
    node.SyncBlocks();
    db->close();
}
