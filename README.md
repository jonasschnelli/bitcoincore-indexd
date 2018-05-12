# External transaction index for Bitcoin Core

[![Build Status](https://travis-ci.org/jonasschnelli/bitcoincore-indexd.svg?branch=master)](https://travis-ci.org/jonasschnelli/bitcoincore-indexd)

### Status
This project is still experimental, use at your own risk!

### How does it work
The indexer connects to a fullnode over the p2p protocol (at the moment 127.0.0.1:8333 mainnet) and performs the following actions:
* opens database
* connect to the peer
* sync all headers, find unindexed blocks
* requests blocks that are not yet indexed
* index all found transactions txid->blockhash
* once all blocks (found via header) has been requested, idle for new inv/block messaged

### Be aware!
The indexer trusts the remote peer! Only connect to a trusted peer, ideally via localhost.
If you connect via the public internet, make sure you connect through a secure channel.

### Database
* The indexer currently works only with leveldb (there was a LMDB implementation, check git history).
* In order to save space, each block will get an internal blockmap-key (uint32 / 4bytes). That internal blockmap-key must not be confused with the block-height. The blockmap-key may be different on other systems/instances.

### Space requirements
* ~14.3GB up to block 522081 (May 10th 2018)
* complete index up to 522081 takes about ~60min on a fast CPU with SSD

### REST interface
* Lookup can be done via HTTP 18445
* Two endpoints
** `/blockhash/<txhash>` will return the blockhash of the requested transaction id
** `/tx/<txhash>` will return the transaction of the requested txid (will fetch the relevant block via p2p and return the tx)

### TODO:
* Reduce memory usage with internal header maps
* Lookup should also respect the non-flushed cache
* Make sure that incoming block invs during sync-via-headers do not confuse the indexer
* Add file based logging
* Add runtime option to switch network (testnet, regtest) and the IP to connect to

### Build
```shell
./autogen.sh
./configure
make -j
```

### run
`./src/bitcoincore-indexd`

Options
* `./src/bitcoincore-indexd --datadir=/tmp` (change datadir, default is ~/.bitcoincore-indexd)
* `./src/bitcoincore-indexd --dbcache=xxx` (change the leveldb dbcache)