extern crate syntax;
use syntax::parse::token;
use syntax::ast;
use syntax::ext::base;
use syntax::ext::deriving::generic;
use syntax::codemap::San;

// macro_rules! is completely broken at the moment, so... let's do it this way.

#[macro_registrar]
pub fn macro_registrar(register: |ast::Name, base::SyntaxExtension|) {
    register(token::intern("deriving_swappable"), base::ItemDecorator(decorator));
}

fn decorator(&mut ExtCtxt, Span, @MetaItem, @Item, |@Item|
fn decorator(cx: &mut ExtCtxt, _span: Span, mitem: @MetaItem, item: @Item, push: |@Item|) { 
    let trait_def = generic::TraitDef {
        span: span,
        attributes: Vec::new(),
        path: Path::new(vec!("util", "Swap")),
        additional_bounds: Vec::new(),
        generics: generic::LifetimeBounds::empty(),
        methods: vec!(
            generic::MethodDef {
                name: "bswap",
                generics: LifetimeBounds::empty(),
                explicit_self: Some(Some(generic::Borrowed(None, ast::MutMutable))),
                args: Vec::new(),
                ret_ty: generic::Tuple(Vec::new()),
                inline: false,
                const_nonmatching: false,
                combine_substructure: |c: &mut base::ExtCtxt, s: Span, sub: &generic::Substructure| {
                    let all_fields = match *sub.fields {
                        Struct(ref af) => { af },
                        _ => fail!()
                    }
                    all_fields.iter().map(|field| {
                        let ident = field.name.unwrap();
                        cx.field_imm(
                        G
                        
                }
            }
        )
    };
    trait_def.expand(cx, mitem, item, push)
}
