
#[derive(Deserialize, Debug)]
struct ConfigFile{
    auth: Vec<Vec<String>>,
    log_level: Option<u8>,
    default_user: Option<String>,
    idle_timeout: Option<i64>,
    redis_url: String,
    listen_url: String,
    healthcheck_listen_url: Option<String>,
    key_rule_read_deny: Vec<Vec<String>>,
    key_rule_read_allow: Vec<Vec<String>>,
    key_rule_write_deny: Vec<Vec<String>>,
    key_rule_write_allow: Vec<Vec<String>>,
    chan_rule_sub_deny: Vec<Vec<String>>,
    chan_rule_sub_allow: Vec<Vec<String>>,
    chan_rule_pub_deny: Vec<Vec<String>>,
    chan_rule_pub_allow: Vec<Vec<String>>,
    cmd_rule_allow: Vec<Vec<String>>,
}



#[derive(Debug)]
struct KeyRule{
    password: String,
    read_deny: Vec<Regex>,
    read_allow: Vec<Regex>,
    write_deny: Vec<Regex>,
    write_allow: Vec<Regex>,
    sub_deny: Vec<Regex>,
    sub_allow: Vec<Regex>,
    pub_deny: Vec<Regex>,
    pub_allow: Vec<Regex>,
    cmd_allow: Vec<CmdType>,
}

#[derive(Debug)]
struct Config {
    default_user: Option<String>,
    listen_url: String,
    redis_url: String,
    key_rule: HashMap<String, KeyRule>,
    idle_timeout: i64,
}

#[derive(Debug)]
#[allow(non_camel_case_types)]
#[derive(PartialEq, Eq, Hash)]
enum CmdType {
    AUTH,
    ADMIN,
    TRANSACTION,
    CONNECTION,
    KEY_R_1, // CMD key
    KEY_R_KEY_LIST, // CMD key [key2 key3 ...]
    KEY_W_1,  // CMD key ...
    KEY_W_KEY_LIST, // CMD key1 [key2,key3...]
    KEY_W_KEY_LIST_L2, // CMD [key1, key2...] param1
    KEY_W_KV_LIST, // CMD key1 value1 [key2 value2 ...]
    KEY_DEST_KEY_LIST_1, // CMD w1 [r1, r2...]
    KEY_DEST_KEY_LIST_2, // CMD param1 w1 [r1, r2...]
    KEY_WSRC_WDEST_1, // CMD w1 w2 [param1, param2...] 
    CMD_STRALGO,
    CMD_KEYS,
    CMD_RANDOMKEY,
    CMD_WAIT,
    CMD_SCAN,
    CMD_PUBSUB,
    CMD_PUB, // CMD chan1 chan2...
    CMD_SUB, // CMD sub1 sub2...
}

struct ConnectionCommand{
    id: u128,
    cmd: u8,
    client_stream: Option<TcpStream>,
    server_stream: Option<TcpStream>,
}
