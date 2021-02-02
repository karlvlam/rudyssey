lazy_static! {

    //static ref LOG_LEVEL:LogLevel = get_log_level(8);

    static ref VALIDATE_KEY_CMD: HashMap<CmdType, fn(&KeyRule, &Vec<String>) -> Option<String> > = {
        let mut m:HashMap<CmdType, fn(&KeyRule, &Vec<String>) -> Option<String> > = HashMap::new();
        m.insert(CmdType::KEY_R_1, validate_key_r_1);
        m.insert(CmdType::KEY_R_KEY_LIST, validate_key_r_key_list);
        m.insert(CmdType::KEY_W_1, validate_key_w_1);
        m.insert(CmdType::KEY_W_KEY_LIST, validate_key_w_key_list);
        m.insert(CmdType::KEY_W_KEY_LIST_L2, validate_key_w_key_list_l2);
        m.insert(CmdType::KEY_W_KV_LIST, validate_key_w_kv_list);
        m.insert(CmdType::KEY_WSRC_WDEST_1, validate_key_wsrc_wdest_1);
        m.insert(CmdType::KEY_DEST_KEY_LIST_1, validate_key_dest_key_list_1);
        m.insert(CmdType::KEY_DEST_KEY_LIST_2, validate_key_dest_key_list_2);
        m.insert(CmdType::CMD_PUB, validate_pub);
        m.insert(CmdType::CMD_SUB, validate_sub);
        m.insert(CmdType::ADMIN, validate_cmd_admin);
        m
    };

    #[derive(Debug)]
    static ref CMD_TYPE: HashMap<&'static str, CmdType> = {
        let mut m = HashMap::new();
        m.insert("AUTH", CmdType::AUTH);

        // Connection
        m.insert("ECHO", CmdType::CONNECTION);
        m.insert("PING", CmdType::CONNECTION);
        m.insert("CLIENT", CmdType::CONNECTION);
        m.insert("QUIT", CmdType::CONNECTION);
        m.insert("RESET", CmdType::CONNECTION);

        // Admin
        m.insert("INFO", CmdType::ADMIN);
        m.insert("CONFIG", CmdType::ADMIN);
        m.insert("MONITOR", CmdType::ADMIN);
        m.insert("FLUSHALL", CmdType::ADMIN);
        m.insert("FLUSHDB", CmdType::ADMIN);


        // GEO
        m.insert("GEOADD", CmdType::KEY_W_1);
        m.insert("GEOHASH", CmdType::KEY_R_1);
        m.insert("GEOPOS", CmdType::KEY_R_1);
        m.insert("GEODIST", CmdType::KEY_R_1);
        m.insert("GEORADIUS", CmdType::KEY_R_1);
        m.insert("GEORADIUSBYMEMBER", CmdType::KEY_R_1);

        // HyperLogLog
        m.insert("PFADD", CmdType::KEY_W_1);
        m.insert("PFCOUNT", CmdType::KEY_R_KEY_LIST);
        m.insert("PFMERGE", CmdType::KEY_DEST_KEY_LIST_1);

        // Hashes
        m.insert("HDEL", CmdType::KEY_W_1);
        m.insert("HEXISTS", CmdType::KEY_R_1);
        m.insert("HGET", CmdType::KEY_R_1);
        m.insert("HGETALL", CmdType::KEY_R_1);
        m.insert("HINCRBY", CmdType::KEY_W_1);
        m.insert("HINCRBYFLOAT", CmdType::KEY_W_1);
        m.insert("HKEYS", CmdType::KEY_R_1);
        m.insert("HLEN", CmdType::KEY_R_1);
        m.insert("HMGET", CmdType::KEY_R_1);
        m.insert("HMSET", CmdType::KEY_W_1);
        m.insert("HSET", CmdType::KEY_W_1);
        m.insert("HSETNX", CmdType::KEY_W_1);
        m.insert("HSTRLEN", CmdType::KEY_R_1);
        m.insert("HVALS", CmdType::KEY_R_1);
        m.insert("HSCAN", CmdType::KEY_R_1);

        // Keys 
        m.insert("COPY", CmdType::KEY_WSRC_WDEST_1);
        m.insert("DEL", CmdType::KEY_W_KEY_LIST);
        m.insert("DUMP", CmdType::KEY_R_1);
        m.insert("EXISTS", CmdType::KEY_R_KEY_LIST);
        m.insert("EXPIRE", CmdType::KEY_W_1);
        m.insert("EXPIREAT", CmdType::KEY_W_1);
        m.insert("KEYS", CmdType::CMD_KEYS);
        // skip MIGRATE
        m.insert("MOVE", CmdType::KEY_W_1);
        // skip OBJECT 
        m.insert("PERSIST", CmdType::KEY_W_1);
        m.insert("PEXPIRE", CmdType::KEY_W_1);
        m.insert("PEXPIREAT", CmdType::KEY_W_1);
        m.insert("PTTL", CmdType::KEY_R_1);
        m.insert("RANDOMKEY", CmdType::CMD_RANDOMKEY); // ?
        m.insert("RENAME", CmdType::KEY_W_KEY_LIST);
        m.insert("RENAMEX", CmdType::KEY_W_KEY_LIST);
        m.insert("RESTORE", CmdType::KEY_W_1);
        m.insert("SORT", CmdType::KEY_W_1);
        m.insert("TOUCH", CmdType::KEY_W_KEY_LIST);
        m.insert("TTL", CmdType::KEY_R_1);
        m.insert("TYPE", CmdType::KEY_R_1);
        m.insert("UNLINK", CmdType::KEY_W_KEY_LIST);
        m.insert("WAIT", CmdType::CMD_WAIT); //?
        m.insert("SCAN", CmdType::CMD_SCAN); //?

        // Lists
        m.insert("BLPOP", CmdType::KEY_W_KEY_LIST_L2);
        m.insert("BRPOP", CmdType::KEY_W_KEY_LIST_L2);
        m.insert("BRPOPLPUSH", CmdType::KEY_WSRC_WDEST_1);
        m.insert("BLMOVE", CmdType::KEY_WSRC_WDEST_1);
        m.insert("LINDEX", CmdType::KEY_R_1);
        m.insert("LINSERT", CmdType::KEY_W_1);
        m.insert("LLEN", CmdType::KEY_R_1);
        m.insert("LPOP", CmdType::KEY_W_1);
        m.insert("LPOS", CmdType::KEY_R_1);
        m.insert("LPUSH", CmdType::KEY_W_1);
        m.insert("LPUSHX", CmdType::KEY_W_1);
        m.insert("LRANGE", CmdType::KEY_R_1);
        m.insert("LREM", CmdType::KEY_W_1);
        m.insert("LSET", CmdType::KEY_W_1);
        m.insert("LTRIM", CmdType::KEY_W_1);
        m.insert("RPOP", CmdType::KEY_W_1);
        m.insert("RPOPLPUSH", CmdType::KEY_WSRC_WDEST_1);
        m.insert("LMOVE", CmdType::KEY_WSRC_WDEST_1);
        m.insert("RPUSH", CmdType::KEY_W_1);
        m.insert("RPUSHX", CmdType::KEY_W_1);

        // Sets 
        m.insert("SADD", CmdType::KEY_W_1);
        m.insert("SCARD", CmdType::KEY_R_1);
        m.insert("SDIFF", CmdType::KEY_R_KEY_LIST);
        m.insert("SDIFFSTORE", CmdType::KEY_DEST_KEY_LIST_1);
        m.insert("SINTER", CmdType::KEY_R_KEY_LIST);
        m.insert("SINTERSTORE", CmdType::KEY_DEST_KEY_LIST_1);
        m.insert("SISMEMBER", CmdType::KEY_R_1);
        m.insert("SMISMEMBER", CmdType::KEY_R_1);
        m.insert("SMEMBERS", CmdType::KEY_R_1);
        m.insert("SMOVE", CmdType::KEY_WSRC_WDEST_1);
        m.insert("SPOP", CmdType::KEY_W_1);
        m.insert("SRANDMEMBER", CmdType::KEY_R_1);
        m.insert("SREM", CmdType::KEY_W_1);
        m.insert("SUNION", CmdType::KEY_R_KEY_LIST);
        m.insert("SUNIONSTORE", CmdType::KEY_DEST_KEY_LIST_1);
        m.insert("SSCAN", CmdType::KEY_W_1);

        // Strings
        m.insert("APPEND", CmdType::KEY_W_1);

        m.insert("BITCOUNT", CmdType::KEY_R_1);
        m.insert("BITFIELD", CmdType::KEY_W_1);
        m.insert("BITTOP", CmdType::KEY_DEST_KEY_LIST_2);

        m.insert("DECR", CmdType::KEY_W_1);
        m.insert("DECRBY", CmdType::KEY_W_1);

        m.insert("GET", CmdType::KEY_R_1);
        m.insert("GETBIT", CmdType::KEY_R_1);
        m.insert("GETRANGE", CmdType::KEY_R_1);
        m.insert("GETSET", CmdType::KEY_W_1);

        m.insert("INC", CmdType::KEY_W_1);
        m.insert("INCRBY", CmdType::KEY_W_1);
        m.insert("INCRBYFLOAT", CmdType::KEY_W_1);

        m.insert("MGET", CmdType::KEY_R_KEY_LIST);
        m.insert("MSET", CmdType::KEY_W_KV_LIST);
        m.insert("MSETNX", CmdType::KEY_W_KV_LIST);

        m.insert("PSETEX", CmdType::KEY_W_1);

        m.insert("SET", CmdType::KEY_W_1);
        m.insert("SETBIT", CmdType::KEY_W_1);
        m.insert("SETEX", CmdType::KEY_W_1);
        m.insert("SETNX", CmdType::KEY_W_1);
        m.insert("SETRANGE", CmdType::KEY_W_1);
        m.insert("STRALGO", CmdType::CMD_STRALGO);
        m.insert("STRLEN", CmdType::KEY_R_1);

        // Pubsub
        m.insert("PUBSUB", CmdType::CMD_PUBSUB);
        m.insert("PUNSUBSCRIBE", CmdType::CMD_PUBSUB);
        m.insert("UNSUBSCRIBE", CmdType::CMD_PUBSUB);
        m.insert("PSUBSCRIBE", CmdType::CMD_SUB);
        m.insert("SUBSCRIBE", CmdType::CMD_SUB);
        m.insert("PUBLISH", CmdType::CMD_PUB);

        // Transactions
        m.insert("DISCARD", CmdType::TRANSACTION);
        m.insert("EXEC", CmdType::TRANSACTION);
        m.insert("MULTI", CmdType::TRANSACTION);
        m.insert("UNWATCH", CmdType::TRANSACTION);
        m.insert("WATCH", CmdType::TRANSACTION);
        m
    };
}

static mut LOG_LEVEL:u8 = 0;

