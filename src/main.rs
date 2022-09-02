mod encryption;

fn main() {
    let mut buffer = "".to_owned();
    let mut stdin = std::io::stdin();
    println!("Enter password: ");
    stdin
        .read_line(&mut buffer)
        .expect("failed to read string from stdin");
    let cipher = encryption::DbEncryption::new(&buffer);
    let mut content = "".to_owned();
    println!("Enter some text: ");
    stdin
        .read_line(&mut content)
        .expect("failed to read string from stdin");
    let ciphertext = cipher.encrypt(&content.as_bytes());
    let mut ciphertext_str = "".to_owned();
    for byte in ciphertext.clone() {
        ciphertext_str.push(char::from(byte));
    }
    println!("ciphertext: {}", ciphertext_str);
    let plaintext = cipher.decrypt(&ciphertext_str.as_bytes());
    let mut plaintext_str = "".to_owned();
    for byte in plaintext.clone() {
        plaintext_str.push(char::from(byte));
    }
    println!("plaintext: {}", plaintext_str);
}
