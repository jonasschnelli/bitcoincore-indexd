// Copyright (c) 2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <btcnode.h>
#include <db_leveldb.h>
#include <httpserver.h>
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

//TODO: turn into shared pointer
IndexDatabaseInterface *g_db = nullptr;

static bool rest_lookup_blockhash(HTTPRequest* req, const std::string& strURIPart)
{
    if (strURIPart.size() != 64) return false;
    std::vector<unsigned char> data = ParseHex(strURIPart);
    if (data.size() != 32) {
        return false;
    }
    std::reverse(data.begin(), data.end()); //we assume big-endian in hex inputs

    Hash256 hash;
    if (g_db->lookupTXID(&data[0], 32, hash)) {
        req->WriteHeader("Content-Type", "text/plain");
        req->WriteReply(HTTP_OK, hash.GetHex());
        return true;
    }
    return false;
}

static bool rest_lookup_tx(HTTPRequest* req, const std::string& strURIPart)
{
    if (strURIPart.size() != 64) return false;
    std::vector<unsigned char> data = ParseHex(strURIPart);
    if (data.size() != 32) {
        return false;
    }
    std::reverse(data.begin(), data.end()); //we assume big-endian in hex inputs

    Hash256 hash;
    if (g_db->lookupTXID(&data[0], 32, hash)) {
        // synchronous fetch the transaction (timeout is 10seconds)
        BTCNode node(nullptr);
        std::vector<unsigned char> txdata;
        if (node.FetchTX(Hash256(&data[0]), hash, txdata)) {
            req->WriteHeader("Content-Type", "text/plain");
            req->WriteReply(HTTP_OK, HexStr(txdata));
            return true;
        }
    }
    return false;
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
    g_db = nullptr;
    if (g_args.GetArg("-database", DEFAULT_DB) == "leveldb") {
        g_db = new DatabaseLEVELDB(GetDataDir()+"/db_leveldb");
    }
    else {
        LogPrintf("Database not supported");
        exit(1);
    }

    InitHTTPServer();
    StartHTTPServer();
    RegisterHTTPHandler("/blockhash/", false, rest_lookup_blockhash);
    RegisterHTTPHandler("/tx/", false, rest_lookup_tx);
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
        if (g_db->lookupTXID(&data[0], 32, hash)) {
            LogPrintf("blockhash: %s\n", hash.GetHex());
        }
        else {
            LogPrintf("Not found\n");
        }
    }
    else {
        // if no lookup, update database
        LogPrintf("start sync...\n");
        BTCNode node(g_db);
        node.SyncLoop();
        g_db->close();
    }
    StopHTTPServer();
}
