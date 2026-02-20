use std::fs;

const W: [u16; 8] = [1, 2, 4, 8, 16, 32, 64, 128];
const M: [u8; 8]  = [0, 1, 2, 3, 4, 5, 6, 7];
const TWEAK: [u16; 5] = [10, 20, 30, 40, 50];

fn enc_knapsack(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() * 2);

    for (i, &b) in data.iter().enumerate() {
        // permute bits (identity here, but keep the structure)
        let mut bb: u8 = 0;
        for src in 0..8 {
            let bit = (b >> src) & 1;
            let dst = M[src as usize];
            bb |= bit << dst;
        }

        // sum weights (with powers of two, this is just bb as u16)
        let mut s: u16 = 0;
        for j in 0..8 {
            if ((bb >> j) & 1) == 1 {
                s = s.wrapping_add(W[j as usize]);
            }
        }

        // easy tweak, no modulo
        s = s.wrapping_add(TWEAK[i % TWEAK.len()]);

        // write big-endian u16
        out.push((s >> 8) as u8);
        out.push((s & 0xFF) as u8);
    }

    out
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} flag.txt encrypted.bin", args[0]);
        return;
    }
    let mut data = fs::read(&args[1]).expect("flag");
    while data.ends_with(b"\n") { data.pop(); }
    let ct = enc_knapsack(&data);
    fs::write(&args[2], ct).expect("write");
}
