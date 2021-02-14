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

                log!("=== BUFFER_IDX: {}, {}", buffer_idx, buffer_idx+byte_count);
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
                log!("=== BUFFER: {}, {}", cur_l, cur_r);
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
                            log!("=== COUNT {}, {}", parse_count, cur_r-cur_l);
                            if parse_count < cur_r - cur_l {
                                buffer_idx_reset = false;
                            }
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
                                                                match server_stream.write(&buffer[cur_l..cur_l+parse_count]).await {
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
                                                        log!("sent buffer {},{}", cur_l, cur_l+parse_count);
                                                        log!("{}", String::from_utf8_lossy(&buffer[cur_l..cur_l+parse_count]));
                                                        match server_stream.write(&buffer[cur_l..cur_l+parse_count]).await {
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



