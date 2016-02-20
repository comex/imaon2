#[macro_use]
extern crate macros;
// super basic

#[derive(Debug, Eq, PartialEq)]
pub enum Sexpr {
    Str(String),
    List(Vec<Sexpr>)
}

#[derive(Debug, Eq, PartialEq)]
pub struct ParseError {
    pos: usize,
    msg: &'static str,
}

pub type ParseResult = Result<Box<Sexpr>, ParseError>;

fn parse_error(pos: usize) -> ParseResult {
    Err(ParseError { pos: pos, msg: "parse error" })
}

pub fn parse_sexpr(s: &str) -> ParseResult {
    let mut it = s.char_indices().peekable();
    let mut stack: Vec<Vec<Sexpr>> = vec![vec![]];
    while let Some((i, ch)) = it.next() {
        if ch == '#' {
            if let Some(&(_, '|')) = it.peek() {
                // block comment
                let mut nesting = 1;
                it.next();
                while let Some((_, ch2)) = it.next() {
                    match (ch2, it.peek()) {
                        ('#', Some(&(_, '|'))) => { nesting += 1; it.next(); },
                        ('|', Some(&(_, '#'))) => {
                            nesting -= 1; 
                            if nesting == 0 { break; }
                            it.next();
                        },
                        _ => ()
                    }
                }
                continue;
            }
        }
        match ch {
        ';' => {
            // line comment
            while let Some((_, ch2)) = it.next() {
                if ch2 == '\n' { break; }
            }
        },
        '(' => {
            stack.push(Vec::new());
        },
        ')' => {
            if stack.len() == 1 {
                return parse_error(i);
            }
            let last = stack.pop().unwrap();
            stack.last_mut().unwrap().push(Sexpr::List(last));
        },
        '"' => {
            // quoted string
            let mut s = String::new();
            loop {
                let (j, ch2) = some_or!(it.next(), { return parse_error(i); });
                match ch2 {
                    '\\' => {
                        let (k, ch3) = some_or!(it.next(), { return parse_error(j); });
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
                                    match it.peek() {
                                        Some(&(_, '\r')) | Some(&(_, '\n')) => { it.next(); continue; },
                                        _ => { break; }
                                    }
                                }
                                None
                            },
                            'x' => {
                                let mut val: u32 = 0;
                                loop {
                                    let (l, ch4) = some_or!(it.next(), { return parse_error(k); });
                                    let ch4u = ch4 as u32;
                                    let digit = match ch4 {
                                        '0' ... '9' => { ch4u - ('0' as u32) },
                                        'a' ... 'f' => { 10 + (ch4u - ('a' as u32)) },
                                        'A' ... 'F' => { 10 + (ch4u - ('A' as u32)) },
                                        ';' => { break; },
                                        _ => { return parse_error(l); }
                                    };
                                    val = (val * 16) + digit;
                                    if val > 0x10ffff {
                                        return Err(ParseError { pos: l, msg: "integer overflow in hex escape" });
                                    }
                                }
                                Some(some_or!(std::char::from_u32(val), {
                                    return Err(ParseError { pos: k, msg: "surrogate in hex escape" });
                                }))
                            },
                            _ => { return parse_error(k) }
                        };
                        if let Some(c) = to_append { s.push(c); }
                    },
                    '"' => { break; },
                    _ => { s.push(ch2); },
                }
            }
            stack.last_mut().unwrap().push(Sexpr::Str(s));
        },
        _ if ch.is_whitespace() => (),
        _ => {
            // a symbol, but here that's just another kind of string
            let mut s = String::new();
            s.push(ch);
            loop {
                match it.peek() {
                    None => { break; },
                    Some(&(j, ch)) => {
                        if ch == '(' || ch == ')' || ch.is_whitespace() { break; }
                        if ch == '"' { return parse_error(j); }
                    }
                }
                s.push(it.next().unwrap().1);
            }
            stack.last_mut().unwrap().push(Sexpr::Str(s));
        }
        }
    }
    // out of chars
    if stack.len() != 1  {
        return parse_error(s.len());
    }
    Ok(Box::new(Sexpr::List(stack.pop().unwrap())))
}

#[test]
fn test_parse_sexpr() {
    let sin = "foo (foo bar(baz)\"boo\\x23;\\r\")";
    println!("{}", sin);
    use Sexpr::*;
    fn s(s: &str) -> Sexpr { Str(s.to_owned()) }
    assert_eq!(parse_sexpr(sin),
        Ok(Box::new(
            List(vec![s("foo"),
                      List(vec![s("foo"), s("bar"), List(vec![s("baz")]),
                                s("boo\x23\r")])]))));

}
