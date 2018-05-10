## External transaction index for Bitcoin Core

#### Status
This project is still experimental, use at your own risk!

#### How does it work
The indexer will build up a connection over the p2p protocol (at the moment 127.0.0.1:8333 mainnet) and performs the following actions:
* open database
* connect to the peer
* sync all headers, figure out if blocks are missing
* requests blocks that are not yet indexed
* once all blocks (found via header) has been requested, idle for new inv/block messaged

#### Be aware!
The indexer trusts the remote peer, only connect to a trusted peer, ideally via localhost.
If you connect via the internet, make sure you connect via a secure channel.

#### Database
* The indexer currently works only with leveldb (there was a LMDB implementation, check git history).
* In order to save space, each block will get an internal blockmap-key (uint32 / 4bytes). That internal blockmap-key must not be confused with the height. The blockmap-key may be different on other systems/instances.

#### Lookups
* WIP: right now, you can lookup a txid via -lookup=<txid>


#### TODO:
* Add http/rest lookups
* Reduce memory usage with internal header maps
* Lookup should also respect the non-flushed cache
* Make sure that incoming block invs during sync-via-headers do not confuse the indexer
* Add file based logging
* Add runtime option to switch network (testnet, regtest) and the IP to connect to
