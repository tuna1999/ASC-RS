fn main() {
    let p = std::env::args().nth(1).unwrap();
    let s = std::fs::read_to_string(&p).unwrap();
    println!("{:?}", asc_core::unbound_locals(&s));
}
