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
use async_std::channel::*;
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
use uuid::Uuid;


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
                                stream.unwrap().shutdown(Shutdown::Both);
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


    let (s, r) = unbounded::<ConnectionCommand>();
    manage_connection(r, s.clone(), config.idle_timeout).await;

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
                            let uuid = Uuid::new_v4();
                            let cid = uuid.as_u128();
                            
                            // register
                            s.send(ConnectionCommand{
                                id:cid, cmd:0, 
                                client_stream:Some(client_stream.clone()), 
                                server_stream:Some(server_stream.clone())
                            }).await;
                          
                            handle_connection(client_stream, server_stream, &config, cid, s.clone()).await;
                        }
                        Err(e) => {
                            error!("{}", e);
                            client_stream.shutdown(Shutdown::Both);
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

async fn kill_connection(cid: u128, s: Sender<ConnectionCommand>) {
    s.send(ConnectionCommand{
        id: cid,
        cmd: 3,
        client_stream: None,
        server_stream: None,
    }).await;
}

async fn manage_connection(r: Receiver<ConnectionCommand>, s: Sender<ConnectionCommand>, idle_timeout: i64){
    log!("start 1");
    #[derive(Debug)]
    struct Connection {
        update_time: i64,
        client_stream: TcpStream,
        server_stream: TcpStream,
    }
    let scanner_sender = s.clone();
   
    spawn(async move {
        let mut connection = HashMap::new();
        loop {
            match r.recv().await {
                Ok(cmd) => {
                    match cmd.cmd {
                        0 => {
                            //info!("0 - register");
                            //info!("{}", cmd.id);
                            let client_stream = cmd.client_stream.unwrap();
                            let server_stream = cmd.server_stream.unwrap();
                            connection.insert(cmd.id, 
                                Connection{
                                    update_time: Utc::now().timestamp(),
                                    client_stream: client_stream, 
                                    server_stream: server_stream
                                }
                            );
                        }
                        1 => {
                            //info!("1 - scan");
                            let now = Utc::now().timestamp();
                            for key in connection.keys() {
                                let mut is_remove = false;
                                match connection.get(key) {
                                    None => {}
                                    Some(o) => {
                                        if  now - o.update_time >= idle_timeout {
                                            info!("IDLE_TIMEOUT: {} -> {} > {}", *key, now - o.update_time, idle_timeout);
                                            kill_connection(*key, s.clone()).await;
                                            /*
                                            s.send(ConnectionCommand{
                                                id: *key,
                                                cmd: 3,
                                                client_stream: None,
                                                server_stream: None,
                                            }).await;
                                            */
                                        }
                                    }
                                }
                                
                            }

                        }
                        2 => {
                            //info!("2 - update timestamp");
                            match connection.get_mut(&cmd.id) {
                                None => {}
                                Some(o) => {
                                    o.update_time = Utc::now().timestamp()
                                }
                            }

                        }
                        3 => {
                            //info!("3 - kill connection");
                            match connection.remove(&cmd.id) {
                                None => {}
                                Some(o) => {
                                    o.client_stream.shutdown(Shutdown::Both);
                                    o.server_stream.shutdown(Shutdown::Both);
                                    info!("SHUTDOWN_CONNECTION: {}", &cmd.id);
                                }
                            }
                            //connection.remove(&cmd.id);
                        }
                        _ => {
                            //info!("unknown");
                        }
                    }
                }
                Err(_e) => {
                    info!("manage_connection Error!");
                }
            }

            //info!("{:?}", connection);

        }
    });
    /*
        */
    spawn(async move {
        log!("Timer Started!");
        loop {
            sleep(Duration::from_millis(5197)).await;
            scanner_sender.send(ConnectionCommand{
                id: 0,
                cmd: 1,
                client_stream: None,
                server_stream: None,
            }).await;

        }
    });

}


async fn handle_connection(client_stream: TcpStream, server_stream: TcpStream, config: &Arc<Config>, cid: u128, s: Sender<ConnectionCommand>){

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

    let server_sender = s.clone();
    let client_sender = s.clone();

    spawn(async move {
        info!("[conn] server connected!");
        // !!! very slow, only use for debugging !!!
        stream_to_stream(server_stream_2, client_stream_2, cid, server_sender.clone(), &config_1).await; 

        // io::copy -> just forward any data from server to client
        //copy_stream(server_stream_2, client_stream_2, "Server").await;

        // close both streams
        //
        kill_connection(cid, server_sender.clone()).await;
        info!("[conn] server disconnected!");
    });

    spawn(async move {
        info!("[conn] client connected!");
        client_to_server(client_stream, server_stream, cid, client_sender.clone(), &config_2).await;

        // close both streams
        kill_connection(cid, client_sender.clone()).await;
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


