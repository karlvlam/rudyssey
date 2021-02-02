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

