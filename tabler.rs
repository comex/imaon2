use std::vec_ng::Vec;
use std::io;
use std::io::File;
use std::io::BufferedReader;

static symbol: &'static str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
static numeric: &'static str = &"0123456789";


struct CharSet([u8, ..256/8]);
impl CharSet {
    fn new() -> CharSet {
        CharSet([0, ..256/8])
    }
    fn with_str(st: &str) -> CharSet {
        let mut s = CharSet::new();
        for c in st.bytes() { s.set(c, true) }
        s
    }
    fn get(&self, idx: u8) -> bool {
        let CharSet(ref a) = self;
        (a[idx / 8] & (1 << (idx & 7))) != 0
    }
    fn set(&mut self, idx: u8, set: bool) {
        let CharSet(ref a) = self;
        let cp = &mut a[idx / 8];
        let off = idx & 7;
        *cp = (cp & ~(1 << off)) | ((set as u8) << off);
    }
}


enum Bit {
    B0,
    B1,
    BUnk,
    BField(~str, int),
}

enum Expr {
    EInt(int),
    EDag(~Expr, Vec<Expr>),
    EList(Vec<Expr>),
    EBits(Vec<Bit>),
    EStr(~str),
    EUnknown,
    ETagged(~str, ~str),
    EIdent(~str),
}

struct Scanner<'r> {
    s: &'r str,
    idx: uint,
}

impl<'r> Scanner<'r> {
    fn new(s: &'r str) -> Scanner<'r> {
        Scanner { s: s, idx: 0 }
    }
    fn word(&mut self, chars: &str) -> &'r str {
        let mut c = '\0';
        while self.idx < self.s.len() && (c = self.s[self.idx])
        
        let mut c = '\0';
        while !self.at_end && 
    }
        
}

fn main() {
    let args = std::os::args();
    let mut r = BufferedReader::new(File::open(&Path::new(args[1])).unwrap());
    while r.read_line().unwrap().as_slice() != "------------- Defs -----------------\n" {}
    loop {
        match r.read_line() {
            Ok(line) => {
                let mut l1 = Scanner::new(line);
                l1.lit("def");
                let name = l1.word(symbol);
                l1.lit("{");
                let classes = Vec::new();
                if !l1.at_end {
                    l1.lit("//");
                    while !l1.at_end {
                        classes.push(l1.word(symbol));
                    }
                }
                loop {
                    let prop = Scanner::new(r.read_line().unwrap());
                    println!(">> {}", prop);
                    if prop == "}\n" { break }
                }
            }
            _ => break
        }
    }

}
