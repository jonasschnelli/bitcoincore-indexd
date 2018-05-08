#include "btcnode.h"

#include <btc/block.h>
#include <btc/net.h>
#include <btc/serialize.h>
#include <btc/tx.h>
#include <btc/utils.h>

#include <utils.h>

class BTCNodePriv
{
public:
    btc_node_group* m_group;
    uint256 m_bestblockhash;
    BTCNode *m_node;
    bool syncblocks;

    BTCNodePriv(BTCNode *node_in);

    ~BTCNodePriv() {
        btc_node_group_free(m_group);
    }

};

btc_bool parse_cmd(struct btc_node_ *node, btc_p2p_msg_hdr *hdr, struct const_buffer *buf)
{
    (void)(node);
    (void)(hdr);
    (void)(buf);
    return true;
}

void request_headers(btc_node *node)
{
    BTCNode *pnode = (BTCNode *)node->nodegroup->ctx;

    // request next headers
    vector *blocklocators = vector_new(1, NULL);
    vector_add(blocklocators, (void *)pnode->GetRawBestBlockHash());

    cstring *getheader_msg = cstr_new_sz(256);
    btc_p2p_msg_getheaders(blocklocators, NULL, getheader_msg);

    /* create p2p message */
    cstring *p2p_msg = btc_p2p_message_new(node->nodegroup->chainparams->netmagic, BTC_MSG_GETHEADERS, getheader_msg->str, getheader_msg->len);
    cstr_free(getheader_msg, true);

    /* send message */
    btc_node_send(node, p2p_msg);
    node->state |= NODE_HEADERSYNC;

    /* cleanup */
    vector_free(blocklocators, true);
    cstr_free(p2p_msg, true);
}

void request_blocks(btc_node *node)
{
    BTCNode *pnode = (BTCNode *)node->nodegroup->ctx;



    cstring* inv_msg_cstr = cstr_new_sz(2000*(4+32));
    int cnt = 0;
    for (HeaderEntry* header : pnode->m_headers) {
        if (header->isRequested()) {
            continue;
        }
        printf("Request block at height: %d\n", header->m_height);
        ser_u32(inv_msg_cstr, MSG_WITNESS_BLOCK);
        ser_bytes(inv_msg_cstr, header->m_hash.m_data, BTC_HASH_LENGTH);
        pnode->m_blocks_in_flight[header->m_hash] = header;
        header->setRequested();
        if (++cnt == 2000) break;
    }

    cstring* inv_msg_cstr_comp = cstr_new_sz(100+2000*(4+32));
    ser_varlen(inv_msg_cstr_comp, cnt);
    cstr_append_cstr(inv_msg_cstr_comp, inv_msg_cstr);
    cstr_free(inv_msg_cstr, true);

    /* create p2p message */
    cstring *p2p_msg = btc_p2p_message_new(node->nodegroup->chainparams->netmagic, BTC_MSG_GETDATA, inv_msg_cstr_comp->str, inv_msg_cstr_comp->len);
    cstr_free(inv_msg_cstr_comp, true);

    /* send message */
    btc_node_send(node, p2p_msg);
    node->state |= NODE_HEADERSYNC;

    /* cleanup */
    cstr_free(p2p_msg, true);
}

void postcmd(struct btc_node_ *node, btc_p2p_msg_hdr *hdr, struct const_buffer *buf)
{
    BTCNode *pnode = (BTCNode *)node->nodegroup->ctx;

    if (strcmp(hdr->command, BTC_MSG_BLOCK) == 0)
    {
        btc_block_header header;
        if (!btc_block_header_deserialize(&header, buf)) return;

        uint32_t vsize;
        if (!deser_varlen(&vsize, buf)) return;

        uint8_t hash[32];
        btc_block_header_hash(&header, hash);

        Hash256 blockhash(hash);
        auto it = pnode->m_blocks_in_flight.find(blockhash);
        if (it != pnode->m_blocks_in_flight.end()) {
            it->second->setLoaded();
        }
        else {
            printf("BLOCK NOT FOUND %s\n", blockhash.GetHex().c_str());
        }
        for (unsigned int i = 0; i < vsize; i++)
        {
            btc_tx *tx = btc_tx_new(); //needs to be on the heep
            size_t len = 0;
            if (!btc_tx_deserialize((const unsigned char *)buf->p, buf->len, tx, &len, true) || len == 0) {
                printf("ERROR\n");
            }
            buf->p = (unsigned char *)buf->p+len;

            uint256 txhash_raw;
            btc_tx_hash(tx, txhash_raw);
            Hash256 txhash(txhash_raw);
            pnode->processTXID(blockhash, txhash);
            btc_tx_free(tx);
        }
        if (!pnode->bestblock || pnode->bestblock->m_height < it->second->m_height) {
            pnode->bestblock = it->second;
            printf("Bestblock at height %s %d\n", pnode->bestblock->m_hash.GetHex().c_str(), pnode->bestblock->m_height );
        }
        //printf("Process block %lld\n", GetTimeMillis()-s);
        //s = GetTimeMillis();
        pnode->m_blocks_in_flight.erase(it);
        if (pnode->m_blocks_in_flight.size() == 0) {
            request_blocks(node);
        }
    }

    if (strcmp(hdr->command, BTC_MSG_HEADERS) == 0)
    {
        uint32_t amount_of_headers;
        if (!deser_varlen(&amount_of_headers, buf)) return;
        node->nodegroup->log_write_cb("Got %d headers\n\n", amount_of_headers);

        for (unsigned int i=0;i<amount_of_headers;i++)
        {
            btc_block_header header;
            if (!btc_block_header_deserialize(&header, buf)) return;
            uint8_t hash[32];
            btc_block_header_hash(&header, hash);
            if (!pnode->AddHeader(hash, header.prev_block)) {
                node->nodegroup->log_write_cb("Failed to connect header\n");
            }
            /* skip tx count */
            if (!deser_skip(buf, 1)) {
                node->nodegroup->log_write_cb("Header deserialization (tx count skip) failed (node %d)\n", node->nodeid);
                return;
            }
        }

        if (amount_of_headers == MAX_HEADERS_RESULTS)
        {
            printf("blockheader: %u\n", pnode->GetHeight());
            /* peer sent maximal amount of headers, very likely, there will be more */
            request_headers(node);
            //request_blocks(node);
        }
        else
        {
            request_blocks(node);
            //btc_node_disconnect(node);
            /* headers download seems to be completed */
            /* we should have switched to block request if the oldest_item_of_interest was set correctly */
        }
    }
}

void node_connection_state_changed(struct btc_node_ *node)
{
    (void)(node);
}

void handshake_done(struct btc_node_ *node)
{
    BTCNode *pnode = (BTCNode *)node->nodegroup->ctx;
    if (!pnode->priv->syncblocks) {
        request_headers(node);
    }
    else {
        // sync blocks
    }
}

BTCNodePriv::BTCNodePriv(BTCNode *node_in) : m_node(node_in) {
    syncblocks = false;
    m_group = btc_node_group_new(NULL);
    m_group->desired_amount_connected_nodes = 1;

    if (g_args.GetBoolArg("-netdebug", false)) {
        m_group->log_write_cb = net_write_log_printf;
    }
    m_group->parse_cmd_cb = parse_cmd;
    m_group->postcmd_cb = postcmd;
    m_group->node_connection_state_changed_cb = node_connection_state_changed;
    m_group->handshake_done_cb = handshake_done;

    m_group->ctx = m_node;

    // push in genesis hash
    m_node->AddHeader((uint8_t*)&m_group->chainparams->genesisblockhash, NULL);
}

BTCNode::BTCNode(IndexDatabaseInterface *db_in) : db(db_in), bestblock(0), priv(new BTCNodePriv(this)) {
    btc_node *node = btc_node_new();
    btc_node_set_ipport(node, "127.0.0.1:8333");
    btc_node_group_add_node(priv->m_group, node);
}


void BTCNode::SyncHeaders() {
    btc_node_group_connect_next_nodes(priv->m_group);
    btc_node_group_event_loop(priv->m_group);
}

void BTCNode::SyncBlocks() {
    priv->syncblocks = true;
    btc_node_group_connect_next_nodes(priv->m_group);
    btc_node_group_event_loop(priv->m_group);
}

bool BTCNode::AddHeader(uint8_t* t, uint8_t* prevhash) {
    if (m_headers.size() > 0 && m_headers.back()->m_hash != prevhash) {
        LogPrintf("Failed to connect header");
        return false;
    }
    HeaderEntry *hEntry = new HeaderEntry(t, m_headers.size());
    m_headers.push_back(hEntry);
    m_blocks[m_headers.back()->m_hash] = hEntry;
    //db->put_header(t, 32, 0, 1);
    return true;
}

void BTCNode::processTXID(const Hash256& block, const Hash256& tx) {
    db->put_txindex(tx.m_data, 32, block.m_data, 32);
}
