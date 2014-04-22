extern crate syntax;
use syntax::parse::token;
use syntax::ast;
use syntax::ext::base;


#[macro_registrar]
pub fn macro_registrar(register: |ast::Name, base::SyntaxExtension|) {
    register(
}
