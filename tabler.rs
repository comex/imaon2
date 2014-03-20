use std::vec_ng::Vec;
use std::io;
use std::io::File;
use std::io::BufferedReader;

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

fn main() {
    let args = std::os::args();
    let mut reader = BufferedReader::new(File::open(&Path::new(args[1])).unwrap());
    while reader.read_line().unwrap().as_slice() != "------------- Defs -----------------\n" {}

}
