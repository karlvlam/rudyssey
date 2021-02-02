
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
        let mut sub_deny:Vec<Regex> = Vec::new();
        let mut sub_allow:Vec<Regex> = Vec::new();
        let mut pub_deny:Vec<Regex> = Vec::new();
        let mut pub_allow:Vec<Regex> = Vec::new();
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

        sub_deny.push(Regex::new("sd1").unwrap());
        sub_deny.push(Regex::new("sd2").unwrap());
        sub_deny.push(Regex::new("sd3").unwrap());

        sub_allow.push(Regex::new("sa1").unwrap());
        sub_allow.push(Regex::new("sa2").unwrap());
        sub_allow.push(Regex::new("sa3").unwrap());

        pub_deny.push(Regex::new("pd1").unwrap());
        pub_deny.push(Regex::new("pd2").unwrap());
        pub_deny.push(Regex::new("pd3").unwrap());

        pub_allow.push(Regex::new("pa1").unwrap());
        pub_allow.push(Regex::new("pa2").unwrap());
        pub_allow.push(Regex::new("pa3").unwrap());



        let key_rule = KeyRule {
            password: "abc123".to_string(),
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

    #[test]
    fn test_validate_sub() {

        let key_rule = &get_key_rule();

        /*** CMD_SUB,  CMD chan1 [chain2, chain3...] ***/

        let c1 = &get_cmd_list(vec!["cmd", "sa1", "sa2"]);
        let c2 = &get_cmd_list(vec!["cmd", "sa1", "hihi"]);
        let c3 = &get_cmd_list(vec!["cmd", "sa1", "sd1"]);

        assert_eq!(validate_sub(key_rule, c1), None);
        assert_ne!(validate_sub(key_rule, c2), None);
        assert_ne!(validate_sub(key_rule, c3), None);

    }

    #[test]
    fn test_validate_pub() {

        let key_rule = &get_key_rule();

        /*** CMD_PUB,  CMD chan value ***/

        let c1 = &get_cmd_list(vec!["cmd", "pa1", "hihi"]);
        let c2 = &get_cmd_list(vec!["cmd", "pd1", "hihi"]);
        let c3 = &get_cmd_list(vec!["cmd", "chan_not_exist", "hihi"]);

        assert_eq!(validate_pub(key_rule, c1), None);
        assert_ne!(validate_pub(key_rule, c2), None);
        assert_ne!(validate_pub(key_rule, c3), None);

    }


}
