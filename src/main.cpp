// Copyright (c) 2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <time.h>

#include <univalue.h>

#include <lmdb.h>

#include <db_lmdb.h>
#include <db_leveldb.h>
#include <btcnode.h>

int main(int argc, char* argv[])
{
    DatabaseLEVELDB db;
    db.open("");
    BTCNode node(&db);
    node.SyncHeaders();
    node.SyncBlocks();
    db.close();
}
