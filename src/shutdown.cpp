// Copyright (c) 2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "shutdown.h"

#include <atomic>

std::atomic<bool> fRequestShutdown(false);

bool isShutdownRequested() {
    return fRequestShutdown;
}
void requestShutdown() {
    fRequestShutdown = true;
}
