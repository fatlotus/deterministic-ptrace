use rand::prelude::*;

fn main() {
    let mut rng = rand::rng();
    let random_number: u32 = rng.random();
    assert_eq!(random_number, 4294521330);
}
