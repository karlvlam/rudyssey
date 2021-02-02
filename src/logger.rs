
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
        if unsafe{ LOG_LEVEL >= 9 } {
            let now: DateTime<Utc> = Utc::now().into();
            let time =  now.format("%FT%T.%3f").to_string();
            print!("{} [TRACE] ", &time);
            println!($($x), *);
        }
    };
}

macro_rules! debug {
    ($($x:expr), *) => {
        if unsafe{ LOG_LEVEL >= 8 } {
            let now: DateTime<Utc> = Utc::now().into();
            let time =  now.format("%FT%T.%3f").to_string();
            print!("{} [DEBUG] ", &time);
            println!($($x), *);
        }
    };
}

macro_rules! warn {
    ($($x:expr), *) => {
        if unsafe{ LOG_LEVEL >= 7} {
            let now: DateTime<Utc> = Utc::now().into();
            let time =  now.format("%FT%T.%3f").to_string();
            print!("{} [WARN] ", &time);
            println!($($x), *);
        }
    };
}

macro_rules! error {
    ($($x:expr), *) => {
        if unsafe{ LOG_LEVEL >= 6 } {
            let now: DateTime<Utc> = Utc::now().into();
            let time =  now.format("%FT%T.%3f").to_string();
            print!("{} [ERROR] ", &time);
            println!($($x), *);
        }
    };
}

macro_rules! info {
    ($($x:expr), *) => {
        if unsafe{ LOG_LEVEL >= 5 } {
            let now: DateTime<Utc> = Utc::now().into();
            let time =  now.format("%FT%T.%3f").to_string();
            print!("{} [INFO] ", &time);
            println!($($x), *);
        }
    };
}


