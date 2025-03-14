use std::os::unix::process::ExitStatusExt;
use clap::{Parser, Subcommand};
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::fs::File;
use std::io::BufRead;

#[derive(Parser)]
#[command(name = "Emergency Shell")]
#[command(about = "A remote shell with XOR-encrypted communication")]
struct Cli {
    #[command(subcommand)]
    mode: Mode,
}

#[derive(Subcommand)]
enum Mode {
    /// Run as server, listening on port 9999
    Server,
    /// Run as client, connecting to server (default: 127.0.0.1:9999)
    Client {
        #[arg(short, long, default_value = "127.0.0.1:9999")]
        address: String,
    },
}

const XOR_KEY: u8 = 0x55;
const END_MARKER: &[u8] = b"\n---END---\n";

fn xor_crypt(data: &[u8]) -> Vec<u8> {
    data.iter().map(|b| b ^ XOR_KEY).collect()
}

fn send_file(stream: &mut TcpStream, filepath: &str) -> io::Result<()> {
    let mut file = File::open(filepath)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    let encrypted_data = xor_crypt(&buffer);
    println!("[Send] Sending file ({} bytes)", encrypted_data.len());
    stream.write_all(&encrypted_data)?;
    stream.flush()?;
    Ok(())
}

fn receive_file(stream: &mut TcpStream, filepath: &str) -> io::Result<()> {
    let mut file = File::create(filepath)?;
    let mut buffer = Vec::new();
    stream.read_to_end(&mut buffer)?;
    let decrypted_data = xor_crypt(&buffer);
    println!("[Receive] Received file ({} bytes)", decrypted_data.len());
    file.write_all(&decrypted_data)?;
    Ok(())
}

fn main() -> io::Result<()> {
    let cli = Cli::parse();
    match cli.mode {
        Mode::Server => run_server(),
        Mode::Client { address } => run_client(&address),
    }
}

fn run_server() -> io::Result<()> {
    let listener = TcpListener::bind("0.0.0.0:9999")?;
    println!("Server listening on port 9999...");
    for stream in listener.incoming() {
        let stream = stream?;
        println!("New connection: {}", stream.peer_addr()?);
        handle_client(stream)?;
    }
    Ok(())
}

fn handle_client(mut stream: TcpStream) -> io::Result<()> {
    let mut buffer = [0u8; 1024];
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => {
                println!("[Server] Connection closed by client");
                break;
            }
            Ok(n) => {
                println!("[Server] Received {} bytes", n);
                let command_bytes = xor_crypt(&buffer[..n]);
                let command = String::from_utf8_lossy(&command_bytes).trim().to_string();
                println!("[Server] Decoded command: {:?}", command);

                if command.is_empty() {
                    continue;
                }

                match command.split_once(' ') {
                    Some(("download", filepath)) => send_file(&mut stream, filepath)?,
                    Some(("upload", filepath)) => receive_file(&mut stream, filepath)?,
                    _ => execute_command(&mut stream, &command)?,
                }
            }
            Err(e) => {
                println!("[Server] Error reading command: {}", e);
                break;
            }
        }
    }
    Ok(())
}

fn execute_command(stream: &mut TcpStream, command: &str) -> io::Result<()> {
    let adjusted_command = if cfg!(target_os = "windows") {
        command.to_string()
    } else if command == "dir" || command == "ls" {
        "ls -l || dir".to_string()
    } else {
        command.to_string()
    };

    let output = if cfg!(target_os = "windows") {
        std::process::Command::new("cmd")
            .arg("/C")
            .arg(&adjusted_command)
            .output()
    } else {
        std::process::Command::new("sh")
            .arg("-c")
            .arg(&adjusted_command)
            .output()
    }.unwrap_or_else(|e| {
        let error = format!("Command failed: {}\n", e);
        std::process::Output {
            status: std::process::ExitStatus::from_raw(1),
            stdout: Vec::new(),
            stderr: error.into_bytes(),
        }
    });

    let stdout_str = String::from_utf8_lossy(&output.stdout);
    let stderr_str = String::from_utf8_lossy(&output.stderr);
    println!("[Server] Command stdout: {:?}", stdout_str);
    println!("[Server] Command stderr: {:?}", stderr_str);

    let encrypted_output = xor_crypt(&output.stdout);
    let encrypted_err = xor_crypt(&output.stderr);
    let encrypted_marker = xor_crypt(END_MARKER);

    let total_size = (encrypted_output.len() + encrypted_err.len()) as u32;
    let mut response = Vec::new();
    response.extend_from_slice(&total_size.to_be_bytes());
    response.extend_from_slice(&encrypted_output);
    response.extend_from_slice(&encrypted_err);
    response.extend_from_slice(&encrypted_marker);

    println!("[Server] Sending total {} bytes (size: 4, stdout: {}, stderr: {}, marker: {})",
             response.len(), encrypted_output.len(), encrypted_err.len(), encrypted_marker.len());
    stream.write_all(&response)?;
    stream.flush()?;
    Ok(())
}

fn run_client(address: &str) -> io::Result<()> {
    let mut stream = TcpStream::connect(address)?;
    println!("Connected to {}", address);

    let mut input = io::stdin().lock();

    loop {
        print!("> ");
        io::stdout().flush()?;

        let mut command = String::new();
        input.read_line(&mut command)?;
        let command = command.trim();
        if command.is_empty() {
            continue;
        }

        let encrypted_command = xor_crypt(format!("{}\n", command).as_bytes());
        println!("[Client] Sending command: {:?}", command);
        stream.write_all(&encrypted_command)?;
        stream.flush()?;

        if command.starts_with("download ") {
            let filepath = command.split_once(' ').unwrap().1;
            receive_file(&mut stream, filepath)?;
            println!("File downloaded: {}", filepath);
        } else if command.starts_with("upload ") {
            let filepath = command.split_once(' ').unwrap().1;
            send_file(&mut stream, filepath)?;
            println!("File uploaded: {}", filepath);
        } else {
            println!("[Client] Waiting for response...");
            let mut size_buf = [0u8; 4];
            stream.read_exact(&mut size_buf)?;
            let total_size = u32::from_be_bytes(size_buf) as usize;
            println!("[Client] Expecting {} bytes of data", total_size);

            let mut response = vec![0u8; total_size];
            stream.read_exact(&mut response)?;
            println!("[Client] Received data: {} bytes", response.len());

            let mut marker_buf = [0u8; 11];
            stream.read_exact(&mut marker_buf)?;
            let encrypted_end_marker = xor_crypt(END_MARKER);
            if marker_buf == *encrypted_end_marker {
                let decrypted_response = xor_crypt(&response);
                let response_str = String::from_utf8_lossy(&decrypted_response);
                println!("[Client] Received response: {:?}", response_str);
                print!("{}", response_str);
                io::stdout().flush()?;
            } else {
                println!("[Client] No END marker found: {:?}", marker_buf);
            }
        }
    }
}
