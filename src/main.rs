mod encryption;

fn split_into_padded_blocks(data: &str) -> Vec<GenericArray<u8, U16>> {
    
}

fn main() {
    let mut buffer = "".to_owned();
    let mut stdin = std::io::stdin();
    stdin.read_line(&mut buffer).expect("failed to read string from stdin");
    
}