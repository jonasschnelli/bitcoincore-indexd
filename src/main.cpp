#include <time.h>

#include <univalue.h>

#include <lmdb.h>

#include <databaselmdb.h>
#include <btcnode.h>


//static unsigned int blocks_in_flight = 0;
//static unsigned int blocks_total = 0;
//static uint256 bestblockhash = {0};
//static btc_bool timer_cb(btc_node *node, uint64_t *now)
//{
//    if (node->time_started_con + 300 < *now)
//        btc_node_disconnect(node);

//    /* return true = run internal timer logic (ping, disconnect-timeout, etc.) */
//    return true;
//}

//static int default_write_log(const char *format, ...)
//{
//    va_list args;
//    va_start(args, format);
//    vprintf(format, args);
//    va_end(args);
//    return 1;
//}

//btc_bool parse_cmd(struct btc_node_ *node, btc_p2p_msg_hdr *hdr, struct const_buffer *buf)
//{
//    (void)(node);
//    (void)(hdr);
//    (void)(buf);
//    return true;
//}

//void request_blockspackage(struct btc_node_ *node);
//void postcmd(struct btc_node_ *node, btc_p2p_msg_hdr *hdr, struct const_buffer *buf)
//{
//    if (strcmp(hdr->command, "block") == 0)
//    {
//        btc_block_header header;
//        if (!btc_block_header_deserialize(&header, buf)) return;

//        uint32_t vsize;
//        if (!deser_varlen(&vsize, buf)) return;

//        blocks_in_flight--;
//        blocks_total++;
//        time_t lasttime = header.timestamp;
//        //printf("block with %d txns (inflight: %d, timestamp: %s)\n", vsize, blocks_in_flight, ctime(&lasttime));
//        for (unsigned int i = 0; i < vsize; i++)
//        {
//            btc_tx *tx = btc_tx_new(); //needs to be on the heep
//            btc_tx_deserialize((const unsigned char *)buf->p, buf->len, tx, NULL, true);

//            btc_tx_free(tx);
//        }
//        if (blocks_in_flight == 0) {
//            char buf[128];
//            utils_bin_to_hex(bestblockhash, 32, buf);
//            printf("Total: %d, best block: %s\n", blocks_total, buf);
//            request_blockspackage(node);
//        }
//    }

//    if (strcmp(hdr->command, "inv") == 0)
//    {
//        // directly create a getdata message
//        cstring *p2p_msg = btc_p2p_message_new(node->nodegroup->chainparams->netmagic, "getdata", buf->p, buf->len);

//        uint32_t vsize;
//        uint8_t hash[36];
//        uint32_t type;
//        if (!deser_varlen(&vsize, buf)) return;

//        printf("INV with %d, total tnsf: %lld MB\n", vsize, node->recv_cnt / 1024 / 1024);
//        for (unsigned int i = 0; i < vsize; i++)
//        {
//            if (!deser_u32(&type, buf)) return;
//            if (!deser_u256(hash, buf)) return;
//            if (type != 2) continue;
//            blocks_in_flight++;
//            memcpy(bestblockhash, hash, 32);
//        }

//        /* send message */
//        btc_node_send(node, p2p_msg);

//        /* cleanup */
//        cstr_free(p2p_msg, true);
//    }

//    if (strcmp(hdr->command, "headers") == 0)
//    {
//        /* send getblock command */

//        /* request some headers (from the genesis block) */
//        vector *blocklocators = vector_new(1, NULL);
//        uint256 from_hash;
//        utils_uint256_sethex("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f", from_hash); // height 428694
//        uint256 stop_hash = {0};

//        vector_add(blocklocators, from_hash);

//        cstring *getheader_msg = cstr_new_sz(256);
//        btc_p2p_msg_getheaders(blocklocators, stop_hash, getheader_msg);

//        /* create p2p message */
//        cstring *p2p_msg = btc_p2p_message_new(node->nodegroup->chainparams->netmagic, "getblocks", getheader_msg->str, getheader_msg->len);
//        cstr_free(getheader_msg, true);

//        /* send message */
//        btc_node_send(node, p2p_msg);

//        /* cleanup */
//        vector_free(blocklocators, true);
//        cstr_free(p2p_msg, true);
//    }
//}

//void node_connection_state_changed(struct btc_node_ *node)
//{
//    (void)(node);
//}

//void request_blockspackage(struct btc_node_ *node) {
//    // request some headers (from the genesis block)
//    vector *blocklocators = vector_new(1, NULL);
//    vector_add(blocklocators, (void *)bestblockhash);

//    cstring *getheader_msg = cstr_new_sz(256);
//    btc_p2p_msg_getheaders(blocklocators, NULL, getheader_msg);

//    /* create p2p message */
//    cstring *p2p_msg = btc_p2p_message_new(node->nodegroup->chainparams->netmagic, "getblocks", getheader_msg->str, getheader_msg->len);
//    cstr_free(getheader_msg, true);

//    /* send message */
//    node->state |= NODE_HEADERSYNC;
//    btc_node_send(node, p2p_msg);

//    /* cleanup */
//    vector_free(blocklocators, true);
//    cstr_free(p2p_msg, true);
    
//    printf("GETBLOCKS request sent\n");
//}

//void handshake_done(struct btc_node_ *node)
//{
//    request_blockspackage(node);
//}

int main(int argc, char* argv[])
{
//    int rc;
//    MDB_env *env;
//    MDB_dbi dbi;
//    MDB_val key, data;
//    MDB_txn *txn;
//    MDB_cursor *cursor;
//    char sval[32];

//    rc = mdb_env_create(&env);
//    rc = mdb_env_open(env, "dummy", 0, 0664);
//    rc = mdb_txn_begin(env, NULL, 0, &txn);
//    rc = mdb_open(txn, NULL, 0, &dbi);
    
//    key.mv_size = sizeof(int);
//    key.mv_data = sval;
//    data.mv_size = sizeof(sval);
//    data.mv_data = sval;
    
//    sprintf(sval, "%03x %d foo bar", 33, 3141592);
//    rc = mdb_put(txn, dbi, &key, &data, 0);
//    rc = mdb_txn_commit(txn);
//    if (rc) fprintf(stderr, "mdb_txn_commit: (%d) %s\n", rc, mdb_strerror(rc));
    
//    rc = mdb_txn_begin(env, NULL, MDB_RDONLY, &txn);
//    rc = mdb_cursor_open(txn, dbi, &cursor);
//    while ((rc = mdb_cursor_get(cursor, &key, &data, MDB_NEXT)) == 0) {
//      printf("key: %p %.*s, data: %p %.*s\n", key.mv_data,  (int) key.mv_size,  (char *) key.mv_data, data.mv_data, (int) data.mv_size, (char *) data.mv_data);
//    }
//    mdb_cursor_close(cursor);
//    mdb_txn_abort(txn);
    
//    mdb_close(env, dbi);
//    mdb_env_close(env);
    
//    btc_node *node = btc_node_new();
//    btc_node_set_ipport(node, "138.201.55.219:8333");
//    //btc_node_set_ipport(node, "127.0.0.1:8333");

//    /* create a node group */
//    btc_node_group* group = btc_node_group_new(NULL);
//    group->desired_amount_connected_nodes = 1;
    
//    /* add the node to the group */
//    btc_node_group_add_node(group, node);

//    /* set the timeout callback */
//    group->periodic_timer_cb = timer_cb;

//    /* set a individual log print function */
//    //group->log_write_cb = net_write_log_printf;
//    group->parse_cmd_cb = parse_cmd;
//    group->postcmd_cb = postcmd;
//    group->node_connection_state_changed_cb = node_connection_state_changed;
//    group->handshake_done_cb = handshake_done;
    
//    memcpy(bestblockhash, node->nodegroup->chainparams->genesisblockhash, 32);

//    /* connect to the next node */
//    btc_node_group_connect_next_nodes(group);

//    /* start the event loop */
//    btc_node_group_event_loop(group);

//    /* cleanup */
//    btc_node_group_free(group); //will also free the nodes structures from the heap


    DatabaseLMDB db;
    db.open("");
    BTCNode node(&db);
    node.SyncHeaders();
    node.SyncBlocks();
    db.close();
}
