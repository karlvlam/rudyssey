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
include!("validation.rs");
include!("parser.rs");

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
    for _i in 1..=3 {
        stream.shutdown(Shutdown::Both);
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

