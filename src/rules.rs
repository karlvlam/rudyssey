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
        let mut sub_deny:Vec<Regex> = Vec::new();
        let mut sub_allow:Vec<Regex> = Vec::new();
        let mut pub_deny:Vec<Regex> = Vec::new();
        let mut pub_allow:Vec<Regex> = Vec::new();
        let mut cmd_allow:Vec<CmdType> = Vec::new();

        parse_rule(&user, &config_file.key_rule_read_deny, &mut read_deny);
        parse_rule(&user, &config_file.key_rule_read_allow, &mut read_allow);
        parse_rule(&user, &config_file.key_rule_write_deny, &mut write_deny);
        parse_rule(&user, &config_file.key_rule_write_allow, &mut write_allow);
        parse_rule(&user, &config_file.chan_rule_sub_deny, &mut sub_deny);
        parse_rule(&user, &config_file.chan_rule_sub_allow, &mut sub_allow);
        parse_rule(&user, &config_file.chan_rule_pub_deny, &mut pub_deny);
        parse_rule(&user, &config_file.chan_rule_pub_allow, &mut pub_allow);
        parse_cmd_rule(&user, &config_file.cmd_rule_allow, &mut cmd_allow);

        let key_rule = KeyRule {
            password,
            read_deny,
            read_allow,
            write_deny,
            write_allow,
            sub_deny,
            sub_allow,
            pub_deny,
            pub_allow,
            cmd_allow,
        };
        m.insert(user, key_rule);
    }

    m    
}


