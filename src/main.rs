#[macro_use]
extern crate lazy_static;
extern crate regex;
extern crate bcrypt;

//use async_std::fs;
use async_std::io::prelude::*;
use async_std::io;
use async_std::net::TcpListener;
use async_std::net::TcpStream;
use async_std::sync::{Arc, Mutex};
//use async_std::task;
use async_std::task::{spawn, sleep};
use futures::stream::StreamExt;
use std::time::Duration;
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
use bcrypt::{hash, verify};


//const TCP_BUFFER_SIZE: usize = 4096;
const TCP_BUFFER_SIZE: usize = 1024 * 4;
const BUFFER_SIZE: usize = 1024 * 64;
const IDEL_TIMEOUT_MIN: i64 = 60;

const ARRAY:u8 = "*".as_bytes()[0];
const STRING:u8 = "$".as_bytes()[0];
const CR:u8 = "\r".as_bytes()[0];
const LF:u8 = "\n".as_bytes()[0];

const ERR_LOGIN_FAIL:&str = "-WRONGPASS invalid username-password pair\r\n";
const ERR_CMD_NOT_SUPPORT:&str = "-RUDYSSEY command not supported\r\n";

include!("logger.rs");
include!("static.rs");
include!("data.rs");
include!("rules.rs");
include!("test.rs");

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
        idle_timeout: match(config_file.idle_timeout) {
            Some(timeout) => {
                if timeout < IDEL_TIMEOUT_MIN{
                    IDEL_TIMEOUT_MIN 
                }else{
                    timeout
                }
            }
            None => {
                IDEL_TIMEOUT_MIN 
            }
        },
        //cmd_type: gen_cmd_type(),
    };
    trace!("{:#?}", &config);
    let config = Arc::new(config);

    // healthcheck listener (optional)
    match config_file.healthcheck_listen_url {
        Some(addr) => {
            spawn(async move {
                match TcpListener::bind(&addr).await {
                    Ok(listener) => {
                        info!("Health check enabled: {}", &addr);
                        listener
                            .incoming()
                            .for_each_concurrent(/* limit */ None, |stream| async {
                                kill_connection(stream.unwrap());
                            }).await;
                    }
                    Err(_e) => {
                        log!("ERROR: health check listener cannot create: {:?}", _e);
                        std::process::exit(1);
                    }
                }
            });

        }
        None => {
        }
    }   



    // Redis Proxy listener
    match TcpListener::bind(&config.listen_url).await {
        Ok(listener) => {
            info!("Redis Proxy listening: {}", &config.listen_url);
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
                            kill_connection(client_stream);
                        }
                }

                })
            .await;
            }
        Err(_e) => {
            log!("ERROR: redis proxy listener cannot create: {:?}", _e);
            std::process::exit(1);
        }
    }

}

fn kill_connection(stream: TcpStream) {
    for i in 1..=3 {
        stream.shutdown(Shutdown::Both);
    }
}

async fn judge_connection(server_stream: TcpStream, client_stream: TcpStream) {

    let m1 = Arc::new(Mutex::new(Utc::now().timestamp()));
    let m2 = m1.clone();

    spawn(async move {
        let mut buffer: [u8; 8] = [0; 8];
        loop {
            match client_stream.peek(&mut buffer).await {
                Ok(byte_count) => {
                    info!("==== get bytes: {}", byte_count);
                    *m1.lock().await = Utc::now().timestamp();
                }
                Err(e) => {
                    error!("{:?}", e);
                }
            }
            //sleep(Duration::from_secs(1)).await;
        }
    });
    //info!("{}", t);
    loop {
        sleep(Duration::from_secs(1)).await;
        info!("====== {}", *m2.lock().await);
    }
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

    let client_stream_5 = client_stream.clone();
    let server_stream_5 = server_stream.clone();
    let config_1 = config.clone();
    let config_2 = config.clone();


    spawn(async move {
        info!("[conn] server connected!");
        // !!! very slow, only use for debugging !!!
        stream_to_stream(server_stream_2, client_stream_2, "Server", &config_1).await; 

        // io::copy -> just forward any data from server to client
        //copy_stream(server_stream_2, client_stream_2, "Server").await;

        // close both streams
        //
        kill_connection(server_stream_3);
        kill_connection(client_stream_3);
        info!("[conn] server disconnected!");
    });

    spawn(async move {
        info!("[conn] client connected!");
        client_to_server(client_stream, server_stream, "Client", &config_2).await;

        // close both streams
        kill_connection(server_stream_4);
        kill_connection(client_stream_4);
        //copy_stream(client_stream, server_stream, "Client").await;
        info!("[conn] client disconnected!");
    });

    /*
       spawn(async move {
       judge_connection(server_stream_5, client_stream_5).await;
       });
       */

}



fn parse_cmd(cmd:&[u8]) -> (Option<String>, Option<Vec<String>>, usize) {
    let cmd_len = cmd.len();
    debug!("STAR: {:?}", CR);
    debug!("vc: {:?}", cmd.len());
    if cmd_len == 0 {
        return (Some("-Error ZERO array".to_string()) , None, 1);
    }

    let mut cmd_list: Vec<String> = Vec::new();
    let mut cur_l:usize = 0;
    let mut cur_r:usize = 0;
    let mut array_len:usize = 0;
    // check first char, should be *
    if cmd[cur_r] != ARRAY {
        debug!("!!! NOT ARRAY !!!");
        return (Some("-Err Not Array".to_string()), None, cur_r + 1);
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
                return (Some("-FORMAT ERROR : Array Length".to_string()), None, cur_r+1);
            }
            if cmd[cur_r+1] != LF {
                debug!("!!! FORMAT ERROR !!!");
                return (Some("-FORMAT ERROR : CRLF".to_string()), None, cur_r+2);
            }

            cur_r += 2;
            break;
        }
        cur_r += 1;
    } 


    // get the command params
    for _i in 0..array_len {
        // avoid index out of range
        if cur_r >= cmd_len {
            debug!("!!! cur_r >= cmd_len: {}, {} !!!", cur_r, cmd_len);
            debug!("{}",String::from_utf8_lossy(&cmd));
            break;
        }

        if cmd[cur_r] != STRING {
            debug!("!!! NOT STRING !!!");
            return (Some("-FORMAT ERROR : NOT STRING".to_string()), None, cur_r+1);
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
                    return (Some("-FORMAT ERROR : param length".to_string()), None, cur_r+1);
                }
                //debug!("Param LEN = {}", param_len);
                if cur_r+1 >= cmd_len {
                    trace!("!!! cur_r >= cmd_len: {}, {} !!!", cur_r, cmd_len);
                    return (Some("GET_PARAM_ERROR".to_string()), None, cur_r+2);
                }


                if cmd[cur_r+1] != LF {
                    debug!("!!! FORMAT ERROR !!!");
                    return (Some("-FORMAT ERROR : CRLF".to_string()), None, cur_r+2);
                }

                cur_r += 2;
                cur_l = cur_r;
                break;
            }
            cur_r += 1;
        }
        // get param_string
        cur_r += param_len as usize;
        if cur_r >= cmd_len || cur_l >= cur_r {
            trace!("!!! cur_r >= cmd_len: {}, {} !!!", cur_r, cmd_len);
            return (Some("GET_PARAM_ERROR".to_string()), None, cur_r+2);
        }

        let param_string = String::from_utf8_lossy(&cmd[cur_l..cur_r]);
        cmd_list.push(param_string.to_string());
        debug!("Param String = '{}'", param_string);

        if cur_r+1 >= cmd_len {
            trace!("!!! cur_r >= cmd_len: {}, {} !!!", cur_r, cmd_len);
            //info!("GET_PARAM_STRING -> {}",String::from_utf8_lossy(&cmd));
            return (Some("GET_PARAM_ERROR".to_string()), None, cur_r+2);
            break;
        }

        if cmd[cur_r] != CR && cmd[cur_r+1] != LF {
            debug!("!!! FORMAT ERROR: param end CRLF !!!" );
            return (Some("-FORMAT ERROR : param end CRLF".to_string()), None, cur_r+2);
        }
        cur_r += 2; //skip CRLF

    }

    if cmd_list.len() + 1 < array_len {
        return (Some("GET_PARAM_ERROR".to_string()), None, cur_r+2);
    }

    (None, Some(cmd_list), cur_r)
}

fn validate_auth_cmd(config: &Arc<Config>, cmd_list: Vec<String>) -> Option<String> {
    debug!("cmd_list: {:?}", &cmd_list );
    let words = cmd_list.len();
    if words == 0 {
        return None;
    }

    if words == 2 {
        // old format: "AUTH passphrase"
        let p = cmd_list.get(1).unwrap(); 

        // TODO: consider String::split_once() after stable
        match p.find(':') {
            None => { return None; }
            Some(idx) => match p.split_at(idx) {
                (user, pre_password) => {
                    let (_, password) =  pre_password.split_at(1);
                    match config.key_rule.get(&user.to_string()) {
                        Some(rule) => {
                            match verify(password, &rule.password.as_str()) {
                                Ok(true) => {
                                    debug!("### Match ! ###");
                                    return Some(user.to_string());
                                }
                                _ => {
                                    debug!("### Login error ###");
                                }
                            }
                        }
                        None => {
                            debug!("### Not Match ! ###");
                        }

                    }

                }
            } 
        }

    }else if words == 3 {
        // new supported format (since redis 6): "AUTH user password"
        let user = cmd_list.get(1).unwrap();
        let password = cmd_list.get(2).unwrap();
        match config.key_rule.get(&user.to_string()) {
            Some(rule) => {
                match verify(password, &rule.password.as_str()) {
                    Ok(true) => {
                        debug!("### Match ! ###");
                        return Some(user.to_string());
                    }
                    _ => {
                        debug!("### Login error ###");
                    }
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

fn validate_sub(key_rule: &KeyRule, cmd_list: &Vec<String>) -> Option<String> {

    //CMD chan1 [chan2, chan3...]
    let words = cmd_list.len();
    if words < 2 {
        return Some("-RUDYSSEY permission issue\r\n".to_string());
    }

    for i in 1..words {

        let k = cmd_list.get(i).unwrap(); 
        for re in &key_rule.sub_deny {
            if re.is_match(k) == true {
                return Some("-RUDYSSEY permission sub_deny match \r\n".to_string());
            }
        }
        let mut deny = true;
        for re in &key_rule.sub_allow {
            if re.is_match(k) == true {
                deny = false;
                break;
            }
        }

        if deny {
            return Some("-RUDYSSEY permission sub_allow doesn't match \r\n".to_string());
        } 
    }

    None

}

fn validate_pub(key_rule: &KeyRule, cmd_list: &Vec<String>) -> Option<String> {

    // CMD chan value 
    let words = cmd_list.len();
    if words < 2 {
        return Some("-RUDYSSEY permission issue\r\n".to_string());
    }


    let k = cmd_list.get(1).unwrap(); 
    for re in &key_rule.pub_deny {
        if re.is_match(k) == true {
            return Some("-RUDYSSEY permission pub_deny match \r\n".to_string());
        }
    }
    let mut deny = true;
    for re in &key_rule.pub_allow {
        if re.is_match(k) == true {
            deny = false;
            break;
        }
    }

    if deny {
        return Some("-RUDYSSEY permission pub_allow doesn't match \r\n".to_string());
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
        Some(CmdType::CMD_PUBSUB) => { Some(CmdType::CMD_PUBSUB) }
        Some(CmdType::CMD_PUB) => { Some(CmdType::CMD_PUB) }
        Some(CmdType::CMD_SUB) => { Some(CmdType::CMD_SUB) }
        Some(CmdType::AUTH) => { Some(CmdType::AUTH) }
        Some(CmdType::CONNECTION) => { Some(CmdType::CONNECTION) }
        Some(CmdType::ADMIN) => { Some(CmdType::ADMIN) }
        _ => None
    } 
}

async fn client_to_server(mut client_stream: TcpStream, mut server_stream: TcpStream, chan:&str, config: &Arc<Config>) {

    let mut tcp_buffer = [0; TCP_BUFFER_SIZE];
    let mut buffer = [0; BUFFER_SIZE ];
    let mut buffer_idx = 0;

    let mut validated_user:Option<String> = None;
    let mut key_rule:Option<&KeyRule> = None;
    match &config.default_user {
        Some(user) => {
            key_rule = config.key_rule.get(user);
        }
        None => {}
    }

    loop{
        match client_stream.read(&mut tcp_buffer).await{
            Ok(byte_count) => {
                if byte_count == 0 {
                    // close connection
                    return;
                }
                let mut buffer_idx_reset = true;

                buffer[buffer_idx..buffer_idx+byte_count].clone_from_slice(&tcp_buffer[0..byte_count]);
                buffer_idx += byte_count;


                debug!("==== CMD ====");
                debug!("{:?}", &buffer[0..byte_count]);
                let cmd = String::from_utf8_lossy(&buffer[0..byte_count]);
                debug!("{}", &cmd);
                if byte_count >= 50 {
                    trace!("==== BYTE_COUNT => {} | {}", byte_count, String::from_utf8_lossy(&tcp_buffer[0..50]).replace("\r\n", " "));
                }
                let mut cur_l:usize = 0;
                let mut cur_r:usize = buffer_idx;
                trace!("=== BUFFER: {}, {}", cur_l, cur_r);
                while cur_l < cur_r {
                    match parse_cmd(&buffer[cur_l..cur_r]) {
                        (Some(s), None, parse_count) => {
                            if s == "GET_PARAM_ERROR".to_string() {
                                trace!("=== NEXT tcp_buffer");
                                buffer_idx_reset = false;
                                break;
                            }
                            debug!("CUR: {}, {}", cur_l, cur_r);
                            debug!("===== parse_cmd error");
                            match client_stream.write(s.as_bytes()).await {
                                Ok(_) => {}
                                Err(e) => {
                                    error!("{}", e);
                                    return;
                                }
                            }
                            cur_l += parse_count;
                        }
                        (None, Some(cmd_list), parse_count) => {
                            debug!("CUR: {}, {}", cur_l, cur_r);
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
                                    cur_l += parse_count;
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

                                            cur_l += parse_count;
                                            continue;
                                        }
                                        Some(key_rule) => {
                                            match cmdtype {

                                                // Read
                                                CmdType::KEY_R_1 | CmdType::KEY_R_KEY_LIST  
                                                    | CmdType::KEY_W_1 | CmdType::KEY_W_KEY_LIST | CmdType::KEY_W_KEY_LIST_L2
                                                    | CmdType::KEY_W_KV_LIST | CmdType::KEY_WSRC_WDEST_1
                                                    | CmdType::KEY_DEST_KEY_LIST_1 | CmdType::KEY_DEST_KEY_LIST_2  
                                                    | CmdType::CMD_PUB | CmdType::CMD_SUB
                                                    | CmdType::ADMIN
                                                    => {
                                                        let validate_fn = &VALIDATE_KEY_CMD.get(&cmdtype).unwrap();
                                                        //match validate_key_r_1(key_rule, &cmd_list) {
                                                        match validate_fn(key_rule, &cmd_list) {
                                                            None => {
                                                                match server_stream.write(&buffer[cur_l..cur_r]).await {
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
                                                    CmdType::CONNECTION | CmdType::CMD_KEYS | CmdType::CMD_PUBSUB => {
                                                        match server_stream.write(&buffer[cur_l..cur_r]).await {
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
                                        cur_l += parse_count;

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
                                        cur_l += parse_count;
                                    }
                                    _ => {
                                        debug!("===== 3c");
                                        match client_stream.write("-RUDYSSEY command not supported\r\n".as_bytes()).await {
                                            Ok(_) => {}
                                            Err(e) => error!("{}", e)
                                        }
                                        cur_l += parse_count;
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
                    if buffer_idx_reset == true {
                        debug!("=== buffer_idx reset");
                        buffer_idx = 0;
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
    //config: &Arc<Config>
    async fn stream_to_stream(mut stream_a: TcpStream,mut stream_b: TcpStream, chan:&str, config: &Arc<Config>) {
        let mut buffer = [0; BUFFER_SIZE];

        let check_time_1 = Arc::new(Mutex::new(Utc::now().timestamp()));
        let check_time_2 = check_time_1.clone();

        let server_stream = stream_a.clone();
        let client_stream = stream_b.clone();
        let idle_timeout = config.idle_timeout;

        spawn(async move {
            loop {
                sleep(Duration::from_millis(5197)).await;
                let current_time = Utc::now().timestamp();
                let last_time = *check_time_1.lock().await;
                let diff_time = current_time - last_time;
                //info!("==== Time diff: {}", diff_time);
                if (diff_time >= idle_timeout) {
                    kill_connection(server_stream);
                    kill_connection(client_stream);
                    info!("==== Time diff > {} ({}), exit!", idle_timeout, diff_time);
                    break;
                }

            }
        });

        loop{
            match stream_a.read(&mut buffer).await{
                Ok(byte_count) => {
                    *check_time_2.lock().await = Utc::now().timestamp();
                    if byte_count == 0 {
                        // close connection
                        info!("==== byte count error!");
                        break;
                    }

                    //debug!("{} stream=> {}, {:?}", chan, byte_count, buffer);
                    //debug!("==== Reply ====");
                    //debug!("{}", String::from_utf8_lossy(&buffer[0..byte_count]));
                    match stream_b.write(&buffer[0..byte_count]).await {
                        Err(e) => {
                            error!("{} stream=> Error: {:?}",chan, e);
                            break;
                        }
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

