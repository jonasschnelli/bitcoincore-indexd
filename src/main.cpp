// Copyright (c) 2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <btcnode.h>
#include <db_leveldb.h>
#include <shutdown.h>
#include <utils.h>

#ifndef WIN32
#include <signal.h>
#endif

static std::string DEFAULT_DB = "leveldb";

#ifndef WIN32
static void registerSignalHandler(int signal, void(*handler)(int))
{
    struct sigaction sa;
    sa.sa_handler = handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(signal, &sa, nullptr);
}
#endif

static void HandleSIGTERM(int)
{
    requestShutdown();
}

int main(int argc, char* argv[])
{
    // parse arguments
    g_args.ParseParameters(argc, argv);

    // create datadir if required
    if (!isDir(GetDataDir()))
    {
        fprintf(stderr, "Error: Specified data directory \"%s\" does not exist.\n", g_args.GetArg("-datadir", "").c_str());
        exit(1);
    }
    CreateDir(GetDataDir());

#ifndef WIN32
    // Clean shutdown on SIGTERM
    registerSignalHandler(SIGTERM, HandleSIGTERM);
    registerSignalHandler(SIGINT, HandleSIGTERM);

    // Ignore SIGPIPE, otherwise it will bring the daemon down if the client closes unexpectedly
    signal(SIGPIPE, SIG_IGN);
#endif

    // flexible database interface
    IndexDatabaseInterface *db = nullptr;
    if (g_args.GetArg("-database", DEFAULT_DB) == "leveldb") {
        db = new DatabaseLEVELDB(GetDataDir()+"/db_leveldb");
    }
    else {
        LogPrintf("Database not supported");
        exit(1);
    }

    // internal lookup (not ideal since it's only possible during startup == always load the DB
    // TODO: move to REST lookup via HTTP
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
