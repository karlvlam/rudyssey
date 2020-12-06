#[macro_use]
extern crate lazy_static;
extern crate regex;

//use async_std::fs;
use async_std::io::prelude::*;
use async_std::io;
use async_std::net::TcpListener;
use async_std::net::TcpStream;
use async_std::sync::{Arc};
use async_std::sync::channel;
//use async_std::task;
use async_std::task::spawn;
use futures::stream::StreamExt;
//use std::time::Duration;
use std::net::Shutdown;
use std::string::String;
use std::collections::HashMap;
use std::fs::read_to_string;
use std::str;
use regex::Regex;
use toml;
use serde::Deserialize;
use chrono::prelude::*;
use chrono::DateTime;


const BUFFER_SIZE: usize = 8192;

const ARRAY:u8 = "*".as_bytes()[0];
const STRING:u8 = "$".as_bytes()[0];
const CR:u8 = "\r".as_bytes()[0];
const LF:u8 = "\n".as_bytes()[0];

const ERR_LOGIN_FAIL:&str = "-WRONGPASS invalid username-password pair\r\n";
const ERR_CMD_NOT_SUPPORT:&str = "-RUDYSSEY command not supported\r\n";


macro_rules! log {
    ($($x:expr), *) => {
        let now: DateTime<Utc> = Utc::now().into();
        let time =  now.format("%FT%T.%3f").to_string();
        print!("{} [LOG] ", &time);
        println!($($x), *);
    };
}

macro_rules! trace {
    ($($x:expr), *) => {
        unsafe {
            if LOG_LEVEL >= 9 {
                let now: DateTime<Utc> = Utc::now().into();
                let time =  now.format("%FT%T.%3f").to_string();
                print!("{} [TRACE] ", &time);
                println!($($x), *);
            }
        }
    };
}

macro_rules! debug {
    ($($x:expr), *) => {
        unsafe {
            if LOG_LEVEL >= 8 {
                let now: DateTime<Utc> = Utc::now().into();
                let time =  now.format("%FT%T.%3f").to_string();
                print!("{} [DEBUG] ", &time);
                println!($($x), *);
            }
        }
    };
}

macro_rules! warn {
    ($($x:expr), *) => {
        unsafe {
            if LOG_LEVEL >= 7{
                let now: DateTime<Utc> = Utc::now().into();
                let time =  now.format("%FT%T.%3f").to_string();
                print!("{} [WARN] ", &time);
                println!($($x), *);
            }
        }
    };
}

macro_rules! error {
    ($($x:expr), *) => {
        unsafe {
            if LOG_LEVEL >= 6{
                let now: DateTime<Utc> = Utc::now().into();
                let time =  now.format("%FT%T.%3f").to_string();
                print!("{} [ERROR] ", &time);
                println!($($x), *);
            }
        }
    };
}

macro_rules! info {
    ($($x:expr), *) => {
        unsafe {
            if LOG_LEVEL >= 5{
                let now: DateTime<Utc> = Utc::now().into();
                let time =  now.format("%FT%T.%3f").to_string();
                print!("{} [INFO] ", &time);
                println!($($x), *);
            }
        }
    };
}


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

#[derive(Deserialize, Debug)]
struct ConfigFile{
    auth: Vec<Vec<String>>,
    log_level: Option<u8>,
    default_user: Option<String>,
    redis_url: String,
    listen_url: String,
    key_rule_read_deny: Vec<Vec<String>>,
    key_rule_read_allow: Vec<Vec<String>>,
    key_rule_write_deny: Vec<Vec<String>>,
    key_rule_write_allow: Vec<Vec<String>>,
    cmd_rule_allow: Vec<Vec<String>>,
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
}


#[derive(Debug)]
struct KeyRule{
    password: String,
    read_deny: Vec<Regex>,
    read_allow: Vec<Regex>,
    write_deny: Vec<Regex>,
    write_allow: Vec<Regex>,
    cmd_allow: Vec<CmdType>,
}

#[derive(Debug)]
struct Config {
    default_user: Option<String>,
    listen_url: String,
    redis_url: String,
    key_rule: HashMap<String, KeyRule>,
}



#[async_std::main]
async fn main() {
    log!("Rudyssey starts...");

    let mut args = std::env::args();

    if args.len() < 2 {
        log!("ERROR: no config file provided!");
        std::process::exit(1);
    }
    let conf_file_name = args.nth(1).unwrap();

    let config_string = match read_to_string(&conf_file_name) {
        Ok(c) => {
            c
        }
        Err(e) => {
            log!("Cannot read file {}", conf_file_name);
            std::process::exit(1);
        }
    };


    let config_file: ConfigFile = toml::from_str(&config_string).unwrap();
    match config_file.log_level {
        Some(n) => { unsafe{ LOG_LEVEL = n } }
        None => {}
    }
    log!("LOG_LEVEL: {}", unsafe{LOG_LEVEL});

    let config = Config {
        default_user: config_file.default_user.clone(),
        listen_url: config_file.listen_url.clone(),
        redis_url: config_file.redis_url.clone(), 
        key_rule: get_key_rule(&config_file),
        //cmd_type: gen_cmd_type(),
    };
    trace!("{:#?}", &config);
    let config = Arc::new(config);

    // Listen for incoming TCP connections on localhost port 7878
    let listener = TcpListener::bind(&config.listen_url).await.unwrap();
    listener
        .incoming()
        .for_each_concurrent(/* limit */ None, |stream| async {
            debug!("Incomming!");
            let client_stream = stream.unwrap();
            match TcpStream::connect(&config.redis_url).await {
                Ok(server_stream) => { 
                    debug!("Connected!");
                    handle_connection(client_stream, server_stream, &config).await;
                }
                Err(e) => {
                    error!("{}", e);
                    //client_stream.shutdown(Shutdown::Both);
                }
            }

        })
    .await;

}

async fn handle_connection(client_stream: TcpStream, server_stream: TcpStream, config: &Arc<Config>){

    info!("handle_connection!");
    // for io::copy
    let client_stream_2 = client_stream.clone();
    let server_stream_2 = server_stream.clone();


    /* 
     * for shutdown connection of another side
     * I know this is on99 stupid, any better solution?
     */
    let client_stream_3 = client_stream.clone();
    let server_stream_3 = server_stream.clone();
    let client_stream_4 = client_stream.clone();
    let server_stream_4 = server_stream.clone();

    let config = config.clone();


    spawn(async move {
        info!("[conn] server connected!");
        // !!! very slow, only use for debugging !!!
        // stream_to_stream(server_stream_2, client_stream_2, "Server").await; 

        // io::copy -> just forward any data from server to client
        copy_stream(server_stream_2, client_stream_2, "Server").await;

        // close both streams
        client_stream_3.shutdown(Shutdown::Both);
        server_stream_3.shutdown(Shutdown::Both);
        info!("[conn] server disconnected!");
    });

    spawn(async move {
        info!("[conn] client connected!");
        client_to_server(client_stream, server_stream, "Client", &config).await;

        // close both streams
        client_stream_4.shutdown(Shutdown::Both);
        server_stream_4.shutdown(Shutdown::Both);
        //copy_stream(client_stream, server_stream, "Client").await;
        info!("[conn] client disconnected!");
    });


}



fn parse_cmd(cmd:&[u8]) -> (Option<String>, Option<Vec<String>>){
    let cmd_len = cmd.len();
    debug!("STAR: {:?}", CR);
    debug!("vc: {:?}", cmd.len());
    if cmd_len == 0 {
        return (Some("-Error ZERO array".to_string()) , None);
    }

    let mut cmd_list: Vec<String> = Vec::new();
    let mut cur_l:usize = 0;
    let mut cur_r:usize = 0;
    let mut array_len:usize = 0;
    // check first char, should be *
    if cmd[cur_r] != ARRAY {
        debug!("!!! NOT ARRAY !!!");
        return (Some("-Err Not Array".to_string()), None);
    }

    cur_l += 1;
    cur_r += 1;

    // get arrary length
    while cur_r < cmd_len {
        if cmd[cur_r] == CR {
            array_len = String::from_utf8_lossy(&cmd[cur_l..cur_r]).parse().unwrap_or(0);
            debug!("Array LEN = {}", array_len);
            if array_len == 0 {
                debug!("!!! FORMAT ERROR : Array Length !!!");
                return (Some("-FORMAT ERROR : Array Length".to_string()), None);
            }
            if cmd[cur_r+1] != LF {
                debug!("!!! FORMAT ERROR !!!");
                return (Some("-FORMAT ERROR : CRLF".to_string()), None);
            }

            cur_r += 2;
            break;
        }
        cur_r += 1;
    } 


    // get the command params
    for _i in 0..array_len {
        if cmd[cur_r] != STRING {
            debug!("!!! NOT STRING !!!");
            return (Some("-FORMAT ERROR : NOT STRING".to_string()), None);
        }
        cur_r += 1;
        cur_l = cur_r;

        let mut param_len:i64 = -1;

        // get param_len
        while cur_r < cmd_len {
            if cmd[cur_r] == CR {
                param_len = String::from_utf8_lossy(&cmd[cur_l..cur_r]).parse().unwrap_or(-1);
                if param_len == -1 {
                    debug!("!!! FORMAT ERROR: param length !!!");
                    return (Some("-FORMAT ERROR : param length".to_string()), None);
                }
                //debug!("Param LEN = {}", param_len);
                if cmd[cur_r+1] != LF {
                    debug!("!!! FORMAT ERROR !!!");
                    return (Some("-FORMAT ERROR : CRLF".to_string()), None);
                }

                cur_r += 2;
                cur_l = cur_r;
                break;
            }
            cur_r += 1;
        }
        // get param_string
        cur_r += param_len as usize;
        let param_string = String::from_utf8_lossy(&cmd[cur_l..cur_r]);
        cmd_list.push(param_string.to_string());
        debug!("Param String = '{}'", param_string);
        if cmd[cur_r] != CR && cmd[cur_r+1] != LF {
            debug!("!!! FORMAT ERROR: param end CRLF !!!" );
            return (Some("-FORMAT ERROR : param end CRLF".to_string()), None);
        }
        cur_r += 2; //skip CRLF

    }

    (None, Some(cmd_list))
}

fn validate_auth_cmd(config: &Arc<Config>, cmd_list: Vec<String>) -> Option<String> {
    debug!("cmd_list: {:?}", &cmd_list );
    let words = cmd_list.len();
    if words == 0 {
        return None;
    }

    if words == 2 {
        let p = cmd_list.get(1).unwrap(); 
        // TODO: handle case with multiple ":"
        let phrases:Vec<&str> = p.split(":").collect();
        if phrases.len() < 2 {
            return None
        }
        let user = phrases.get(0).unwrap();
        let password = phrases.get(1).unwrap();

        match config.key_rule.get(&user.to_string()) {
            Some(rule) => {
                if &rule.password == password {
                    debug!("### Match ! ###");
                    return Some(user.to_string());
                }
            }
            None => {
                debug!("### Not Match ! ###");
            }

        }
    }else if words == 3 {
        let user = cmd_list.get(1).unwrap();
        let password = cmd_list.get(2).unwrap();
        match config.key_rule.get(&user.to_string()) {
            Some(rule) => {
                if &rule.password == password {
                    debug!("### Match ! ###");
                    return Some(user.to_string());
                }
            }
            None => {
                debug!("### Not Match ! ###");
            }
        }
    }


    None

}

fn validate_cmd_admin (key_rule: &KeyRule, cmd_list: &Vec<String>) -> Option<String> {
    // CMD key

    for ct in &key_rule.cmd_allow{
        if ct == &CmdType::ADMIN {
            return None;
        }
    }

    Some("-RUDYSSEY permission cmd_allow::ADMIN doesn't match \r\n".to_string())
}

fn validate_key_w_1 (key_rule: &KeyRule, cmd_list: &Vec<String>) -> Option<String> {
    // CMD key
    let words = cmd_list.len();
    if words < 2 {
        return Some("-RUDYSSEY permission issue\r\n".to_string());
    }

    let k = cmd_list.get(1).unwrap(); 
    for re in &key_rule.write_deny {
        if re.is_match(k) == true {
            return Some("-RUDYSSEY permission write_deny match \r\n".to_string());
        }
    }
    for re in &key_rule.write_allow {
        if re.is_match(k) == true {
            return None;
        }
    }

    Some("-RUDYSSEY permission write_allow doesn't match \r\n".to_string())

}

fn validate_key_w_kv_list (key_rule: &KeyRule, cmd_list: &Vec<String>) -> Option<String> {

    // CMD key1 value1 [key2 value2 ...]
    let words = cmd_list.len();
    if words < 3 {
        return Some("-RUDYSSEY permission issue\r\n".to_string());
    }

    let mut i = 1;
    while i < words {

        let k = cmd_list.get(i).unwrap(); 
        debug!("idx: {}, key: {}", i, k);
        for re in &key_rule.write_deny {
            if re.is_match(k) == true {
                return Some("-RUDYSSEY permission write_deny match \r\n".to_string());
            }
        }

        let mut allowed = false;
        for re in &key_rule.write_allow {
            if re.is_match(k) == true {
                allowed = true;
                break;
            }
        }

        if allowed == false {
            return Some("-RUDYSSEY permission write_allow doesn't match \r\n".to_string());
        }

        i += 2;
    }

    None

}

fn validate_key_w_key_list_l2 (key_rule: &KeyRule, cmd_list: &Vec<String>) -> Option<String> {

    // CMD key1 value1 [key2 value2 ...]
    let words = cmd_list.len();
    if words < 3 {
        return Some("-RUDYSSEY permission issue\r\n".to_string());
    }

    let mut i = 1;
    while i < words - 1 {
        debug!("idx: {}", i);

        let k = cmd_list.get(i).unwrap(); 
        for re in &key_rule.write_deny {
            if re.is_match(k) == true {
                return Some("-RUDYSSEY permission write_deny match \r\n".to_string());
            }
        }

        let mut deny = true;
        for re in &key_rule.write_allow {
            if re.is_match(k) == true {
                deny = false;
                break;
            }
        }

        if deny {
            return Some("-RUDYSSEY permission write_allow doesn't match \r\n".to_string());
        }
        i += 1;
    }

    None

}

fn validate_key_dest_key_list_1 (key_rule: &KeyRule, cmd_list: &Vec<String>) -> Option<String> {

    // CMD w1 r1 [r2 r3...]
    let words = cmd_list.len();
    if words < 3 {
        return Some("-RUDYSSEY permission issue\r\n".to_string());
    }

    // write key
    let k = cmd_list.get(1).unwrap(); 
    for re in &key_rule.write_deny {
        if re.is_match(k) == true {
            return Some("-RUDYSSEY permission write_deny match \r\n".to_string());
        }
    }

    let mut deny = true;
    for re in &key_rule.write_allow {
        if re.is_match(k) == true {
            deny = false;
            break;
        }
    }
    if deny {
        return Some("-RUDYSSEY permission write_allow doesn't match \r\n".to_string());
    }

    // read key list
    let mut i = 2;
    while i < words {
        debug!("idx: {}", i);

        let k = cmd_list.get(i).unwrap(); 
        for re in &key_rule.read_deny {
            if re.is_match(k) == true {
                return Some("-RUDYSSEY permission read_deny match \r\n".to_string());
            }
        }

        let mut deny = true;
        for re in &key_rule.read_allow {
            if re.is_match(k) == true {
                deny = false;
                break
            }
        }
        if deny {
            return Some("-RUDYSSEY permission read_allow doesn't match \r\n".to_string());
        }
        i += 1;
    }

    None

}

fn validate_key_dest_key_list_2 (key_rule: &KeyRule, cmd_list: &Vec<String>) -> Option<String> {

    // CMD param1 w1 r1 [r2 r3...]
    let words = cmd_list.len();
    if words < 4 {
        return Some("-RUDYSSEY permission issue\r\n".to_string());
    }

    // write key
    let k = cmd_list.get(2).unwrap(); 
    for re in &key_rule.write_deny {
        if re.is_match(k) == true {
            return Some("-RUDYSSEY permission write_deny match \r\n".to_string());
        }
    }

    let mut deny = true;
    for re in &key_rule.write_allow {
        if re.is_match(k) == true {
            deny = false;
            break;
        }
    }
    if deny {
        return Some("-RUDYSSEY permission write_allow doesn't match \r\n".to_string());
    }

    // read key list
    let mut i = 3;
    while i < words {
        debug!("idx: {}", i);

        let k = cmd_list.get(i).unwrap(); 
        for re in &key_rule.read_deny {
            if re.is_match(k) == true {
                return Some("-RUDYSSEY permission read_deny match \r\n".to_string());
            }
        }

        let mut deny = true;
        for re in &key_rule.read_allow {
            if re.is_match(k) == true {
                deny = false;
                break
            }
        }
        if deny {
            return Some("-RUDYSSEY permission read_allow doesn't match \r\n".to_string());
        }
        i += 1;
    }

    None

}


fn validate_key_wsrc_wdest_1 (key_rule: &KeyRule, cmd_list: &Vec<String>) -> Option<String> {

    // CMD w1 w2 [param1 param2 ...]
    let words = cmd_list.len();
    if words < 3 {
        return Some("-RUDYSSEY permission issue\r\n".to_string());
    }

    let mut i = 1;
    while i < 3 {
        debug!("idx: {}", i);

        let k = cmd_list.get(i).unwrap(); 
        for re in &key_rule.write_deny {
            if re.is_match(k) == true {
                return Some("-RUDYSSEY permission write_deny match \r\n".to_string());
            }
        }
        let mut deny = true;
        for re in &key_rule.write_allow {
            if re.is_match(k) == true {
                deny = false;
                break;
            }
        }
        if deny {
            return Some("-RUDYSSEY permission write_allow doesn't match \r\n".to_string());
        }
        i += 1;
    }

    None

}



fn validate_key_r_1 (key_rule: &KeyRule, cmd_list: &Vec<String>) -> Option<String> {
    // CMD key
    let words = cmd_list.len();
    if words < 2 {
        return Some("-RUDYSSEY permission issue\r\n".to_string());
    }

    let k = cmd_list.get(1).unwrap(); 
    for re in &key_rule.read_deny {
        if re.is_match(k) == true {
            return Some("-RUDYSSEY permission read_deny match \r\n".to_string());
        }
    }
    for re in &key_rule.read_allow {
        if re.is_match(k) == true {
            return None;
        }
    }

    Some("-RUDYSSEY permission read_allow doesn't match \r\n".to_string())

}

fn validate_key_w_key_list (key_rule: &KeyRule, cmd_list: &Vec<String>) -> Option<String> {

    // CMD key1 [key2 key3 ...]
    let words = cmd_list.len();
    if words < 2 {
        return Some("-RUDYSSEY permission issue\r\n".to_string());
    }

    for i in 1..words {

        let k = cmd_list.get(i).unwrap(); 
        for re in &key_rule.write_deny {
            if re.is_match(k) == true {
                return Some("-RUDYSSEY permission write_deny match \r\n".to_string());
            }
        }
        let mut deny = true;
        for re in &key_rule.write_allow {
            if re.is_match(k) == true {
                deny = false;
                break;
            }
        }

        if deny {
            return Some("-RUDYSSEY permission write_allow doesn't match \r\n".to_string());
        }
    }

    None

}

fn validate_key_r_key_list (key_rule: &KeyRule, cmd_list: &Vec<String>) -> Option<String> {

    //CMD key [key2 key3...]
    let words = cmd_list.len();
    if words < 2 {
        return Some("-RUDYSSEY permission issue\r\n".to_string());
    }

    for i in 1..words {

        let k = cmd_list.get(i).unwrap(); 
        for re in &key_rule.read_deny {
            if re.is_match(k) == true {
                return Some("-RUDYSSEY permission read_deny match \r\n".to_string());
            }
        }
        let mut deny = true;
        for re in &key_rule.read_allow {
            if re.is_match(k) == true {
                deny = false;
                break;
            }
        }

        if deny {
            return Some("-RUDYSSEY permission read_allow doesn't match \r\n".to_string());
        } 
    }

    None

}


fn get_cmd_type(cmd_list: &Vec<String>) -> Option<CmdType> {
    let cmd_type = &CMD_TYPE;
    if cmd_list.len() == 0 {
        return None;
    }
    match cmd_type.get(&cmd_list.get(0).unwrap().to_uppercase().as_str()) {
        Some(CmdType::KEY_R_1) => { Some(CmdType::KEY_R_1) }
        Some(CmdType::KEY_R_KEY_LIST) => { Some(CmdType::KEY_R_KEY_LIST) }

        Some(CmdType::KEY_DEST_KEY_LIST_1) => { Some(CmdType::KEY_DEST_KEY_LIST_1) }
        Some(CmdType::KEY_DEST_KEY_LIST_2) => { Some(CmdType::KEY_DEST_KEY_LIST_2) }

        Some(CmdType::KEY_W_1) => { Some(CmdType::KEY_W_1) }
        Some(CmdType::KEY_W_KV_LIST) => { Some(CmdType::KEY_W_KV_LIST) }
        Some(CmdType::KEY_W_KEY_LIST) => { Some(CmdType::KEY_W_KEY_LIST) }
        Some(CmdType::KEY_WSRC_WDEST_1) => { Some(CmdType::KEY_WSRC_WDEST_1) }
        Some(CmdType::KEY_W_KEY_LIST_L2) => { Some(CmdType::KEY_W_KEY_LIST_L2) }

        Some(CmdType::CMD_KEYS) => { Some(CmdType::CMD_KEYS) }
        Some(CmdType::AUTH) => { Some(CmdType::AUTH) }
        Some(CmdType::ADMIN) => { Some(CmdType::ADMIN) }
        _ => None
    } 
}

async fn client_to_server(mut client_stream: TcpStream, mut server_stream: TcpStream, chan:&str, config: &Arc<Config>) {

    let mut buffer = [0; BUFFER_SIZE];

    let mut validated_user:Option<String> = None;
    let mut key_rule:Option<&KeyRule> = None;
    match &config.default_user {
        Some(user) => {
            key_rule = config.key_rule.get(user);
        }
        None => {}
    }

    loop{
        match client_stream.read(&mut buffer).await{
            Ok(byte_count) => {
                if byte_count == 0 {
                    // close connection
                    return;
                }


                debug!("==== CMD ====");
                let cmd = String::from_utf8_lossy(&buffer[0..byte_count]);
                debug!("{}", &cmd);
                let mut cur_l:usize = 0;
                let mut cur_r:usize = byte_count;
                {
                    match parse_cmd(&buffer[cur_l..cur_r]) {
                        (Some(s), None) => {
                            debug!("===== parse_cmd error");
                            match client_stream.write(s.as_bytes()).await {
                                Ok(_) => {}
                                Err(e) => {
                                    error!("{}", e);
                                    return;
                                }
                            }
                        }
                        (None, Some(cmd_list)) => {
                            debug!("===== 2");
                            match get_cmd_type(&cmd_list){
                                Some(CmdType::AUTH) => {
                                    debug!("===== CMD AUTH");
                                    match validate_auth_cmd(config, cmd_list) {
                                        Some(user) => {
                                            key_rule = config.key_rule.get(&user);
                                            validated_user = Some(user);
                                            debug!("{:?}", &validated_user);
                                            debug!("{:?}", &key_rule);
                                            match client_stream.write("+OK\r\n".as_bytes()).await {
                                                Ok(_) => {}
                                                Err(e) => {
                                                    error!("{}", e);
                                                    return;
                                                }
                                            }
                                        }
                                        None => {
                                            match client_stream.write(ERR_LOGIN_FAIL.as_bytes()).await {
                                                Ok(_) => {}
                                                Err(e) => {
                                                    error!("{}", e);
                                                    return;
                                                }
                                            }
                                        }
                                    }
                                }
                                Some(cmdtype) => {
                                    match key_rule {
                                        // no login
                                        None => {
                                            match client_stream.write("-RUDYSSEY please login first\r\n".as_bytes()).await {
                                                Ok(_) => {}
                                                Err(e) => {
                                                    error!("{}", e);
                                                    return;
                                                }
                                            }


                                            continue;
                                        }
                                        Some(key_rule) => {
                                            match cmdtype {

                                                // Read
                                                CmdType::KEY_R_1 | CmdType::KEY_R_KEY_LIST  
                                                    | CmdType::KEY_W_1 | CmdType::KEY_W_KEY_LIST | CmdType::KEY_W_KEY_LIST_L2
                                                    | CmdType::KEY_W_KV_LIST | CmdType::KEY_WSRC_WDEST_1
                                                    | CmdType::KEY_DEST_KEY_LIST_1 | CmdType::KEY_DEST_KEY_LIST_2  
                                                    | CmdType::ADMIN
                                                    => {
                                                        let validate_fn = &VALIDATE_KEY_CMD.get(&cmdtype).unwrap();
                                                        //match validate_key_r_1(key_rule, &cmd_list) {
                                                        match validate_fn(key_rule, &cmd_list) {
                                                            None => {
                                                                match server_stream.write(&buffer[0..byte_count]).await {
                                                                    Ok(_) => {}
                                                                    Err(e) => {
                                                                        error!("{}", e);
                                                                        return;
                                                                    }
                                                                }
                                                            }
                                                            Some(s) => {
                                                                match client_stream.write(s.as_bytes()).await {
                                                                    Ok(_) => {}
                                                                    Err(e) => {
                                                                        error!("{}", e);
                                                                        return;
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }

                                                    // Public 
                                                    CmdType::CONNECTION | CmdType::CMD_KEYS => {
                                                        match server_stream.write(&buffer[0..byte_count]).await {
                                                            Ok(_) => {}
                                                            Err(e) => {
                                                                error!("{}", e);
                                                                return;
                                                            }
                                                        }
                                                    }

                                                    _ => {
                                                        match client_stream.write(ERR_CMD_NOT_SUPPORT.as_bytes()).await {
                                                            Ok(_) => {}
                                                            Err(e) => {
                                                                error!("{}", e);
                                                                return;
                                                            }
                                                        }
                                                    }
                                                    }
                                            }

                                        }

                                    }
                                    None => {
                                        debug!("===== 3b");
                                        match client_stream.write("-RUDYSSEY command not supported\r\n".as_bytes()).await{
                                            Ok(_) => {}
                                            Err(e) => {
                                                error!("{}", e);
                                                return;
                                            }
                                        }
                                    }
                                    _ => {
                                        debug!("===== 3c");
                                        match client_stream.write("-RUDYSSEY command not supported\r\n".as_bytes()).await {
                                            Ok(_) => {}
                                            Err(e) => error!("{}", e)
                                        }
                                    }
                                }
                            }

                            _ => {
                                match client_stream.write("-UNKNOWN_ERROR".as_bytes()).await {
                                    Ok(_) => {}
                                    Err(e) => error!("{}", e)
                                }
                            }
                        }
                    }

                }
                Err(_e) => {
                    error!("{} stream=> Error: {:?}",chan, _e);
                    break;
                }
            }
        }

    }


    // copy, fast and easy
    async fn copy_stream(stream_a: TcpStream, stream_b: TcpStream, chan:&str) {
        match io::copy(stream_a, stream_b).await {
            Err(e) => {
                error!("{}", e);
            }
            _ => {
            }
        }
    }

    // copy, slow and debug
    async fn stream_to_stream(mut stream_a: TcpStream,mut stream_b: TcpStream, chan:&str) {
        let mut buffer = [0; BUFFER_SIZE];
        loop{
            match stream_a.read(&mut buffer).await{
                Ok(byte_count) => {
                    if byte_count == 0 {
                        // close connection
                        break;
                    }

                    debug!("{} stream=> {}, {:?}", chan, byte_count, buffer);
                    debug!("==== Reply ====");
                    debug!("{}", String::from_utf8_lossy(&buffer[0..byte_count]));
                    match stream_b.write(&buffer[0..byte_count]).await {
                        _ => {}
                    }
                }
                Err(e) => {
                    error!("{} stream=> Error: {:?}",chan, e);
                    break;
                }
            }
        }

    }

    fn get_key_rule(config_file: &ConfigFile) -> HashMap<String, KeyRule> {
        fn parse_rule(user: &String, rule: &Vec<Vec<String>>, target_rule: &mut Vec<Regex>) {
            for rule_list in rule {
                if rule_list.len() < 2 {
                    continue;
                }
                match rule_list.get(0) {
                    None => {
                        continue;
                    }
                    Some(n) => {
                        if n != user {
                            continue;
                        }
                    }
                }
                for j in 1..rule_list.len() {
                    match rule_list.get(j) {
                        None => {
                            continue;
                        }
                        Some(s) => {
                            let re = Regex::new(&s).unwrap();
                            target_rule.push(re);
                        }
                    }

                }
            }

        }

        fn parse_cmd_rule(user: &String, rule: &Vec<Vec<String>>, target_rule: &mut Vec<CmdType>) {
            for rule_list in rule {
                if rule_list.len() < 2 {
                    continue;
                }
                match rule_list.get(0) {
                    None => {
                        continue;
                    }
                    Some(n) => {
                        if n != user {
                            continue;
                        }
                    }
                }
                for j in 1..rule_list.len() {
                    match rule_list.get(j) {
                        None => {
                            continue;
                        }
                        Some(s) => {
                            match s.as_str() {
                                "ADMIN" => { target_rule.push(CmdType::ADMIN); }
                                "TRANSACTION" => { target_rule.push(CmdType::TRANSACTION); }
                                _ => {}
                            }
                        }
                        _ => {
                            continue;
                        }
                    }

                }
            }

        }

        //let config_file: ConfigFile = toml::from_str(&s).unwrap();
        let mut m:HashMap<String, KeyRule> = HashMap::new(); 
        for i in &config_file.auth {
            if i.len() < 2 {
                continue;
            }
            let user = i.get(0).unwrap().to_string();
            let password = i.get(1).unwrap().to_string();
            let mut read_deny:Vec<Regex> = Vec::new();
            let mut read_allow:Vec<Regex> = Vec::new();
            let mut write_deny:Vec<Regex> = Vec::new();
            let mut write_allow:Vec<Regex> = Vec::new();
            let mut cmd_allow:Vec<CmdType> = Vec::new();

            parse_rule(&user, &config_file.key_rule_read_deny, &mut read_deny);
            parse_rule(&user, &config_file.key_rule_read_allow, &mut read_allow);
            parse_rule(&user, &config_file.key_rule_write_deny, &mut write_deny);
            parse_rule(&user, &config_file.key_rule_write_allow, &mut write_allow);
            parse_cmd_rule(&user, &config_file.cmd_rule_allow, &mut cmd_allow);

            let key_rule = KeyRule {
                password,
                read_deny,
                read_allow,
                write_deny,
                write_allow,
                cmd_allow,
            };
            m.insert(user, key_rule);
        }

        m    
    }

    /*
     * Test Cases
     * */
#[cfg(test)]
    mod tests {

        use super::*;

        fn get_cmd_list(list:Vec<&str>) -> Vec<String> {
            let mut cmdlist:Vec<String> = Vec::new();
            for s in list {
                cmdlist.push(s.to_string());
            }
            cmdlist
        }

        fn get_key_rule() -> KeyRule {
            let mut read_deny:Vec<Regex> = Vec::new();
            let mut read_allow:Vec<Regex> = Vec::new();
            let mut write_deny:Vec<Regex> = Vec::new();
            let mut write_allow:Vec<Regex> = Vec::new();
            let mut cmd_allow:Vec<CmdType> = Vec::new();

            read_deny.push(Regex::new("rd1").unwrap());
            read_deny.push(Regex::new("rd2").unwrap());
            read_deny.push(Regex::new("rd3").unwrap());

            read_allow.push(Regex::new("ra1").unwrap());
            read_allow.push(Regex::new("ra2").unwrap());
            read_allow.push(Regex::new("ra3").unwrap());

            write_deny.push(Regex::new("wd1").unwrap());
            write_deny.push(Regex::new("wd2").unwrap());
            write_deny.push(Regex::new("wd3").unwrap());

            write_allow.push(Regex::new("wa1").unwrap());
            write_allow.push(Regex::new("wa2").unwrap());
            write_allow.push(Regex::new("wa3").unwrap());


            let key_rule = KeyRule {
                password: "abc123".to_string(),
                read_deny,
                read_allow,
                write_deny,
                write_allow,
                cmd_allow,
            };

            key_rule
        }

        #[test]
        fn test_validate_key_r_1() {
            let key_rule = &get_key_rule();
            /*
               KEY_R_1, // CMD key
               */
            let c1 = &get_cmd_list(vec!["cmd", "ra1"]);
            let c2 = &get_cmd_list(vec!["cmd", "ra2"]);
            let c3 = &get_cmd_list(vec!["cmd", "nokey"]);
            let c4 = &get_cmd_list(vec!["cmd", "nokey"]);

            assert_eq!(validate_key_r_1(key_rule, c1), None);
            assert_eq!(validate_key_r_1(key_rule, c2), None);
            assert_ne!(validate_key_r_1(key_rule, c3), None);
            assert_ne!(validate_key_r_1(key_rule, c4), None);
        }


        #[test]
        fn test_validate_key_r_key_list() {

            let key_rule = &get_key_rule();
            /*
               KEY_R_KEY_LIST, // CMD key [key2 key3 ...]
               */
            let c1 = &get_cmd_list(vec!["cmd", "ra1", "ra2"]);
            let c2 = &get_cmd_list(vec!["cmd", "ra1", "nokey"]);

            assert_eq!(validate_key_r_key_list(key_rule, c1), None);
            assert_ne!(validate_key_r_key_list(key_rule, c2), None);

        }

        #[test]
        fn test_validate_key_w_1() {

            let key_rule = &get_key_rule();

            /** KEY_W_1 -> CMD key ... **/
            let c1 = &get_cmd_list(vec!["cmd", "wa2"]);
            let c2 = &get_cmd_list(vec!["cmd", "nokey"]);
            let c3 = &get_cmd_list(vec!["cmd", "wd1"]);

            assert_eq!(validate_key_w_1(key_rule, c1), None);
            assert_ne!(validate_key_w_1(key_rule, c2), None);
            assert_ne!(validate_key_w_1(key_rule, c3), None);

        }

        #[test]
        fn test_validate_key_w_key_list() {

            let key_rule = &get_key_rule();

            /*** KEY_W_KEY_LIST,  CMD key1 [key2,key3...] ***/

            let c1 = &get_cmd_list(vec!["cmd", "wa1", "wa2", "wa3"]);
            let c2 = &get_cmd_list(vec!["cmd", "wa1", "wa2", "hello"]);

            assert_eq!(validate_key_w_key_list(key_rule, c1), None);
            assert_ne!(validate_key_w_key_list(key_rule, c2), None);

        }

        #[test]
        fn test_validate_key_w_key_list_l2() {

            let key_rule = &get_key_rule();

            /*** KEY_W_KEY_LIST_L2, // CMD [key1, key2...] param1 ***/

            let c1 = &get_cmd_list(vec!["cmd", "wa1", "wa2", "wa3", "param1"]);
            let c2 = &get_cmd_list(vec!["cmd", "wa1", "wa2", "hello"]);
            let c3 = &get_cmd_list(vec!["cmd", "wa1", "wa2", "hello", "param1"]);

            assert_eq!(validate_key_w_key_list_l2(key_rule, c1), None);
            assert_eq!(validate_key_w_key_list_l2(key_rule, c2), None);
            assert_ne!(validate_key_w_key_list_l2(key_rule, c3), None);

        }

        #[test]
        fn test_validate_key_w_kv_list() {

            let key_rule = &get_key_rule();

            /*** KEY_W_KV_LIST, // CMD key1 value1 [key2 value2 ...] ***/

            let c1 = &get_cmd_list(vec!["cmd", "wa1", "value1", "wa2", "value2"]);
            let c2 = &get_cmd_list(vec!["cmd", "wa1", "value1", "wd1", "value2"]);
            let c3 = &get_cmd_list(vec!["cmd", "wa1", "value1", "nokey", "value2"]);

            assert_eq!(validate_key_w_kv_list(key_rule, c1), None);
            assert_ne!(validate_key_w_kv_list(key_rule, c2), None);
            assert_ne!(validate_key_w_kv_list(key_rule, c3), None);

        }

        #[test]
        fn test_validate_key_dest_key_list_1() {

            let key_rule = &get_key_rule();

            /*** KEY_DEST_KEY_LIST_1, // CMD w1 [r1, r2...] ***/

            let c1 = &get_cmd_list(vec!["cmd", "wa1", "ra1", "ra2"]);
            let c2 = &get_cmd_list(vec!["cmd", "wa1", "ra1", "r-nokey"]);
            let c3 = &get_cmd_list(vec!["cmd", "wd1", "ra1", "ra2"]);
            let c4 = &get_cmd_list(vec!["cmd", "w-nokey", "ra1", "ra2"]);

            assert_eq!(validate_key_dest_key_list_1(key_rule, c1), None);
            assert_ne!(validate_key_dest_key_list_1(key_rule, c2), None);
            assert_ne!(validate_key_dest_key_list_1(key_rule, c3), None);
            assert_ne!(validate_key_dest_key_list_1(key_rule, c4), None);

        }

        #[test]
        fn test_validate_key_dest_key_list_2() {

            let key_rule = &get_key_rule();

            /*** KEY_DEST_KEY_LIST_2, // CMD param1 w1 [r1, r2...] ***/

            let c1 = &get_cmd_list(vec!["cmd", "param1", "wa1", "ra1", "ra2"]);
            let c2 = &get_cmd_list(vec!["cmd", "param1", "wa1", "ra1", "r-nokey"]);
            let c3 = &get_cmd_list(vec!["cmd", "param1", "wd1", "ra1", "ra2"]);
            let c4 = &get_cmd_list(vec!["cmd", "param1", "w-nokey", "ra1", "ra2"]);

            assert_eq!(validate_key_dest_key_list_2(key_rule, c1), None);
            assert_ne!(validate_key_dest_key_list_2(key_rule, c2), None);
            assert_ne!(validate_key_dest_key_list_2(key_rule, c3), None);
            assert_ne!(validate_key_dest_key_list_2(key_rule, c4), None);

        }

        #[test]
        fn test_validate_key_wsrc_wdest_1() {

            let key_rule = &get_key_rule();

            /*** KEY_WSRC_WDEST_1, // CMD w1 w2 [param1, param2...] ***/

            let c1 = &get_cmd_list(vec!["cmd", "wa1", "wa2", "haha"]);
            let c2 = &get_cmd_list(vec!["cmd", "wa1", "ra2", "haha"]);
            let c2 = &get_cmd_list(vec!["cmd", "ra1", "wa1", "haha"]);

            assert_eq!(validate_key_wsrc_wdest_1(key_rule, c1), None);
            assert_ne!(validate_key_wsrc_wdest_1(key_rule, c2), None);

        }

    }
