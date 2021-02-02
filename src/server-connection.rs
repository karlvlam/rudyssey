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

