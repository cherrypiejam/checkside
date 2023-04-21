use std::io::stdin;

fn main() {
    let mut guess = String::new();
    if let Ok(_) = stdin().read_line(&mut guess) {
        if guess.trim_end().eq("secret") {
            println!("success!");
        } else {
            println!("Oops, try another time.");
        }
    }
}
