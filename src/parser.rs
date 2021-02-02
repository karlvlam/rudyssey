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

