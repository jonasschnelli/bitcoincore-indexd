## External transaction index for Bitcoin Core

#### Status
This project is still experimental, use at your own risk!

#### How does it work
The indexer connects to a fullnode over the p2p protocol (at the moment 127.0.0.1:8333 mainnet) and performs the following actions:
* opens database
* connect to the peer
* sync all headers, find unindexed blocks
* requests blocks that are not yet indexed
* index all found transactions txid->blockhash
* once all blocks (found via header) has been requested, idle for new inv/block messaged

#### Be aware!
The indexer trusts the remote peer! Only connect to a trusted peer, ideally via localhost.
If you connect via the public internet, make sure you connect through a secure channel.

#### Database
* The indexer currently works only with leveldb (there was a LMDB implementation, check git history).
* In order to save space, each block will get an internal blockmap-key (uint32 / 4bytes). That internal blockmap-key must not be confused with the block-height. The blockmap-key may be different on other systems/instances.

#### Space requirements
* ~14.3GB up to block 522081 (May 10th 2018)
* complete index up to 522081 takes about ~60min on a fast CPU with SSD

#### Lookups
* Lookup can be done via HTTP 18445 (-rpcport). Example `curl 127.0.0.1:5442/5012c1d2a46d5684aa0331f0d8a900767c86c0fd83bb632f357b1ea11fa69179`


#### TODO:
* Reduce memory usage with internal header maps
* Lookup should also respect the non-flushed cache
* Make sure that incoming block invs during sync-via-headers do not confuse the indexer
* Add file based logging
* Add runtime option to switch network (testnet, regtest) and the IP to connect to
* http lookup: fetch block from peer and return tx