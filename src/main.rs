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
const TCP_BUFFER_SIZE: usize = 4099 * 1;
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
include!("server-connection.rs");
include!("client-connection.rs");

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


