// Copyright (c) 2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <btcnode.h>
#include <db_leveldb.h>
#include <utils.h>

static std::string DEFAULT_DB = "leveldb";
int main(int argc, char* argv[])
{
    // parse arguments
    g_args.ParseParameters(argc, argv);

    // create datadir if required
    CreateDir(GetDataDir());

    // flexible database interface
    IndexDatabaseInterface *db = nullptr;
    if (g_args.GetArg("-database", DEFAULT_DB) == "leveldb") {
        db = new DatabaseLEVELDB(GetDataDir()+"/db_leveldb");
    }
    else {
        LogPrintf("Database not supported");
        exit(1);
    }

    // internal lookup (not ideal since its only possible during startup == always load the DB
    // todo: move to REST lookup via HTTP
    if (g_args.GetArg("-lookup", "") != "") {
        std::vector<unsigned char> data = ParseHex(g_args.GetArg("-lookup", ""));
        if (data.size() != 32) {
            LogPrintf("invalid hash\n");
            exit(1);
        }
        std::reverse(data.begin(), data.end()); //we assume big-endian in hex inputs
        Hash256 hash;
        if (db->lookupTXID(&data[0], 32, hash)) {
            LogPrintf("blockhash: %s\n", hash.GetHex());
        }
        else {
            LogPrintf("Not found\n");
        }
    }
    else {
        // if no lookup, update database
        LogPrintf("start sync...\n");
        BTCNode node(db);
        node.SyncHeaders();
        node.SyncBlocks();
        db->close();
    }
}
