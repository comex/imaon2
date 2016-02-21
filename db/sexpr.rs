// super basic

#![feature(io)]
#[macro_use]
extern crate macros;

use std::io::{BufRead, CharsError, Cursor, Write};

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

fn comments_error() -> ReadResult {
    Err(ReadError::ParseError("inner comments not allowed (because they will be stripped when it's written back out)"))
}

macro_rules! insert { ($stack:expr, $e:expr) => { {
    let e = $e;
    if let Some(last) = $stack.last_mut() {
        last.push(e);
    } else {
        return Ok(Box::new(e));
    }
} } }

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

#[derive(Debug, PartialEq, Eq)]
pub enum CommentBehavior {
    AllowComments,
    BanInnerComments,
}
pub use CommentBehavior::*;

pub fn read_sexpr<R: BufRead>(r: R, cb: CommentBehavior) -> ReadResult {
    let mut it = r.chars().peekable();
    let mut stack: Vec<Vec<Sexpr>> = vec![];
    while let Some(ch) = intry!(it.next()) {
        if ch == '#' {
            if let Some('|') = intry_peek!(it) {
                // block comment
                if cb == BanInnerComments && stack.len() > 0 {
                    return comments_error();
                }
                let mut nesting = 1;
                it.next();
                let mut s = String::new();
                while let Some(ch2) = intry!(it.next()) {
                    match (ch2, intry_peek!(it)) {
                        ('#', Some('|')) => {
                            nesting += 1;
                            it.next();
                            s.push('#'); s.push('|');
                        },
                        ('|', Some('#')) => {
                            nesting -= 1;
                            it.next();
                            if nesting == 0 { break; }
                            s.push('|'); s.push('#');
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
            if cb == BanInnerComments && stack.len() > 0 {
                return comments_error();
            }
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

// based on R6Rs
fn valid_symbol_initial_char(c: char) -> bool {
    // this is an underapproximation in not allowing Unicode letters (todo)
    match c {
        '!' | '$' | '%' | '&' | '*' | '/' | ':' | '<' | '=' |
        'a'...'z' | 'A'...'Z' => true,
        _ => false
    }
}
fn valid_symbol_inner_char(c: char) -> bool {
    if valid_symbol_initial_char(c) { return true; }
    match c {
        '0' ... '9' | '+' | '-' | '.' | '@' => true,
        _ => false
    }
}
fn niceish_char(_c: char) -> bool {
    true // TODO (anything but " and \ can go in quotes but only pretty things should)
}
#[derive(Debug, PartialEq, Eq)]
enum ReadNumberError {
    ParseError,
    OutOfRange,
}
const PE: Result<u64, ReadNumberError> = Err(ReadNumberError::ParseError);
fn read_number(s: &str) -> Result<u64, ReadNumberError> {
    let mut radix: Option<u8> = None;
    let mut have_eness = false;
    let mut it = s.chars();
    let mut c2 = None;
    while let Some(c) = it.next() {
        if c == '#' {
            let next = some_or!(it.next(), { return PE });
            match next {
                'i' | 'I' | 'e' | 'E' => { // exactness
                    if have_eness { return PE }
                    have_eness = true;
                    continue;
                },
                _ => ()
            }
            // radix
            if radix.is_some() { return PE }
            radix = Some(match next {
                'x' | 'X' => 16,
                'd' | 'D' => 10,
                'o' | 'O' => 8,
                'b' | 'B' => 2,
                _ => {
                    // huh?
                    return PE
                }
            });
        } else {
            c2 = Some(c);
            break;
        }
    }
    let mut c2 = if let Some(c2) = c2 { c2 } else { some_or!(it.next(), { return PE }) };
    let radix = radix.unwrap_or(10);
    // sign?
    let mut num = Some(0u64);
    let mut got_digits = false;
    match c2 {
        '+' | '-' => {
            if c2 == '-' { num = None; }
            c2 = some_or!(it.next(), { return PE });
        },
        _ => (),
    }
    // the digits
    loop {
        match c2 {
            'e' | 'E' | 's' | 'S' | 'f' | 'F' | 'd' | 'D' | 'l' | 'L' => {
                // exponent (integers only)
                let mut c3 = it.next();
                match c3 {
                    Some('+') => { c3 = it.next(); },
                    Some('-') => { num = None; c3 = it.next(); },
                    _ => (),
                }
                let mut expo = Some(0u32);
                loop {
                    match c3 {
                        Some(cc@'0'...'9') => {
                            let digit = cc as u32 - '0' as u32;
                            expo = expo.and_then(|e| e.checked_mul(10)).and_then(|m| m.checked_add(digit));
                        },
                        None => { break },
                        _ => { return PE }
                    }
                    c3 = it.next();
                }
                num = if let Some(e@0...19) = expo {
                    num.and_then(|n| n.checked_mul(10u64.pow(e)))
                } else { None };
            },
            _ => {
                let digit = some_or!(c2.to_digit(radix as u32), { return PE });
                num = num.and_then(|n| n.checked_mul(radix as u64))
                         .and_then(|n| n.checked_add(digit as u64));
                got_digits = true;
            }
        }
        c2 = some_or!(it.next(), { break });
    }
    if !got_digits {
        return PE;
    }
    if let Some(num) = num {
        Ok(num)
    } else {
        Err(ReadNumberError::OutOfRange)
    }
}


pub fn write_sexpr<W: Write>(mut w: W, sx0: &Sexpr) -> std::io::Result<()> {
    let mut need_white = false;
    let mut stack: Vec<&[Sexpr]> = vec![];
    let mut sx = sx0;
    loop {
        println!(">>> {:?}", stack);
        if need_white {
            try!(write!(w, " "));
        }
        match sx {
            &Sexpr::Str(ref s) => {
                let mut cit = s.chars();
                let first = cit.next();
                if first.is_some() && (
                    (valid_symbol_initial_char(first.unwrap()) &&
                     cit.all(valid_symbol_inner_char)) ||
                    read_number(s).is_ok()
                ) {
                    try!(write!(w, "{}", s));
                } else {
                    try!(write!(w, "\""));
                    for c in s.chars() {
                        let escape = match c {
                            '\\' => Some('\\'),
                            '"'  => Some('"'),
                            '\r' => Some('r'),
                            '\n' => Some('n'),
                            '\t' => Some('t'),
                            _ => None,
                        };
                        if let Some(c) = escape {
                            try!(write!(w, "\\{}", c));
                        } else if !niceish_char(c) {
                            try!(write!(w, "\\x{:x};", c as u32));
                        } else {
                            try!(write!(w, "{}", c));
                        }
                    }
                    try!(write!(w, "\""));
                }
                need_white = true;
            },
            &Sexpr::List(ref v) => {
                try!(write!(w, "("));
                stack.push(&v[..]);
                need_white = false;
            },
            &Sexpr::LineComment(ref s) => {
                try!(write!(w, ";{}\n", s));
                need_white = false;

            },
            &Sexpr::BlockComment(ref s) => {
                // todo: check for |# inside?
                try!(write!(w, "#|{}|#", s));
                need_white = true;
            },

        }
        {
            while some_or!(stack.last(), { return Ok(()) }).len() == 0 {
                try!(write!(w, ")"));
                need_white = true;
                stack.pop().unwrap();
            }
            let mut last = stack.last_mut().unwrap();
            let first = &(*last)[0];
            *last = &(*last)[1..];
            sx = first;
        }
    }
}

fn s(s: &str) -> Sexpr { Sexpr::Str(s.to_owned()) }

#[test]
fn test_read_sexpr() {
    let sin = "(foo (foo bar(#| 1 #| 2 |# |#baz)\"boo\\x23;\\r\") ; comment\n)";
    let mut cursor = Cursor::new(sin);
    //println!("{}", sin);
    use Sexpr::*;
    let res = read_sexpr(&mut cursor, AllowComments).unwrap();
    assert_eq!(cursor.position(), sin.len() as u64);
    assert_eq!(*res,
            List(vec![s("foo"),
                      List(vec![s("foo"),
                                s("bar"),
                                List(vec![BlockComment(" 1 #| 2 |# ".to_owned()),
                                          s("baz")]),
                                s("boo\x23\r")]),
                      LineComment(" comment".to_owned())]));
    assert!(read_sexpr(&mut Cursor::new(sin), BanInnerComments).is_err());

}

#[test]
fn test_read_number() {
    assert_eq!(read_number("1234"), Ok(1234));
    assert_eq!(read_number("#x1234"), Ok(0x1234));
    assert_eq!(read_number("#x#i1234"), Ok(0x1234));
    assert_eq!(read_number("#i#x1234"), Ok(0x1234));
    assert_eq!(read_number("#x#i#x1234"), PE);
    assert_eq!(read_number("#i#i#x1234"), PE);
    assert_eq!(read_number("1234e+5"), Ok(123400000));
    assert_eq!(read_number("1234e-1"), Err(ReadNumberError::OutOfRange));
    assert_eq!(read_number("-1"), Err(ReadNumberError::OutOfRange));
    assert_eq!(read_number("18446744073709551616"), Err(ReadNumberError::OutOfRange));
}

#[test]
fn test_write_sexpr() {
    use Sexpr::*;
    let foo =
        List(vec![s("foo"),
                  List(vec![s("foo"),
                            LineComment("hi!".to_owned()),
                            s("bar"),
                            List(vec![BlockComment(" 1 #| 2 |# ".to_owned()),
                                      s("baz")]),
                            s("boo\x23\r")])]);
    let mut buf: Vec<u8> = Vec::new();
    assert!(write_sexpr(&mut buf, &foo).is_ok());
    let res = String::from_utf8(buf).unwrap();
    assert_eq!(res, "(foo (foo ;hi!\nbar (#| 1 #| 2 |# |# baz) \"boo#\\r\"))");

}

