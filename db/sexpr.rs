// super basic

#![feature(io)]
#[macro_use]
extern crate macros;

use std::io::{BufRead, CharsError, Cursor};

#[derive(Debug, Eq, PartialEq)]
pub enum Sexpr {
    Str(String),
    List(Vec<Sexpr>),
    LineComment(String),
    BlockComment(String),
}

#[derive(Debug)]
pub enum ReadError {
    ParseError(&'static str),
    Chars(CharsError),
}

pub type ReadResult = Result<Box<Sexpr>, ReadError>;

fn parse_error() -> ReadResult {
    Err(ReadError::ParseError("parse error"))
}

macro_rules! test { ($foo:expr) => { } }

macro_rules! insert { ($stack:expr, $e:expr) => {
    if let Some(last) = $stack.last_mut() {
        last.push($e);
    } else {
        return Ok(Box::new($e));
    }
} }

// Option<Result<X>> -> Option<X> (+ Chars wrap)
macro_rules! intry { ($val:expr) => {
    match $val {
        None => None,
        Some(Ok(v)) => Some(v),
        Some(Err(e)) => { return Err(ReadError::Chars(e)) },
    }
} }
macro_rules! intry_peek { ($it:expr) => {
    match $it.peek() {
        None => None,
        Some(&Ok(v)) => Some(v),
        Some(&Err(_)) => { return Err(ReadError::Chars($it.next().unwrap().unwrap_err())) },
    }
} }

pub fn read_sexpr<R: BufRead>(r: R) -> ReadResult {
    let mut it = r.chars().peekable();
    let mut stack: Vec<Vec<Sexpr>> = vec![];
    while let Some(ch) = intry!(it.next()) {
        if ch == '#' {
            if let Some('|') = intry_peek!(it) {
                // block comment
                let mut nesting = 1;
                it.next();
                let mut s = String::new();
                while let Some(ch2) = intry!(it.next()) {
                    match (ch2, intry_peek!(it)) {
                        ('#', Some('|')) => { nesting += 1; it.next(); },
                        ('|', Some('#')) => {
                            nesting -= 1;
                            if nesting == 0 { break; }
                            s.push(ch2);
                            s.push(it.next().unwrap().unwrap());
                        },
                        _ => s.push(ch2),
                    }
                }
                insert!(stack, Sexpr::BlockComment(s));
                continue;
            }
        }
        match ch {
        ';' => {
            // line comment
            let mut s = String::new();
            while let Some(ch2) = intry!(it.next()) {
                if ch2 == '\n' { break; }
                s.push(ch2);
            }
            insert!(stack, Sexpr::LineComment(s));
        },
        '(' => {
            stack.push(Vec::new());
        },
        ')' => {
            let last = some_or!(stack.pop(), { return parse_error(); });
            insert!(stack, Sexpr::List(last));
        },
        '"' => {
            // quoted string
            let mut s = String::new();
            loop {
                let ch2 = some_or!(intry!(it.next()), { return parse_error(); });
                match ch2 {
                    '\\' => {
                        let ch3 = some_or!(intry!(it.next()), { return parse_error(); });
                        let to_append = match ch3 {
                            'a' => Some('\x07'),
                            'b' => Some('\x08'),
                            't' => Some('\t'),
                            'n' => Some('\n'),
                            'v' => Some('\x0b'),
                            'f' => Some('\x0c'),
                            'r' => Some('\r'),
                            '"' => Some('"'),
                            '\\' => Some('\\'),
                            '\r' | '\n' => {
                                loop {
                                    match intry_peek!(it) {
                                        Some('\r') | Some('\n') => { it.next(); continue; },
                                        _ => { break; }
                                    }
                                }
                                None
                            },
                            'x' => {
                                let mut val: u32 = 0;
                                loop {
                                    let ch4 = some_or!(intry!(it.next()), { return parse_error(); });
                                    let ch4u = ch4 as u32;
                                    let digit = match ch4 {
                                        '0' ... '9' => { ch4u - ('0' as u32) },
                                        'a' ... 'f' => { 10 + (ch4u - ('a' as u32)) },
                                        'A' ... 'F' => { 10 + (ch4u - ('A' as u32)) },
                                        ';' => { break; },
                                        _ => { return parse_error(); }
                                    };
                                    val = (val * 16) + digit;
                                    if val > 0x10ffff {
                                        return Err(ReadError::ParseError("integer overflow in hex escape"));
                                    }
                                }
                                Some(some_or!(std::char::from_u32(val), {
                                    return Err(ReadError::ParseError("surrogate in hex escape"));
                                }))
                            },
                            _ => { return parse_error() }
                        };
                        if let Some(c) = to_append { s.push(c); }
                    },
                    '"' => { break; },
                    _ => { s.push(ch2); },
                }
            }
            insert!(stack, Sexpr::Str(s));
        },
        _ if ch.is_whitespace() => (),
        _ => {
            // a symbol, but here that's just another kind of string
            let mut s = String::new();
            s.push(ch);
            loop {
                match intry_peek!(it) {
                    None => { break; },
                    Some(ch) => {
                        if ch == '(' || ch == ')' || ch.is_whitespace() { break; }
                        if ch == '"' { return parse_error(); }
                    }
                }
                s.push(it.next().unwrap().unwrap());
            }
            insert!(stack, Sexpr::Str(s));
        }
        }
    }
    // out of chars
    parse_error()
}

#[test]
fn test_parse_sexpr() {
    test!(panic!());
    let sin = "(foo (foo bar(baz)\"boo\\x23;\\r\"))";
    let mut cursor = Cursor::new(sin);
    println!("{}", sin);
    use Sexpr::*;
    fn s(s: &str) -> Sexpr { Str(s.to_owned()) }
    let res = read_sexpr(&mut cursor).unwrap();
    assert_eq!(cursor.position(), sin.len() as u64);
    assert_eq!(*res,
            List(vec![s("foo"),
                      List(vec![s("foo"), s("bar"), List(vec![s("baz")]),
                                s("boo\x23\r")])]));

}
