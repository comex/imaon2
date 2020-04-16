#[macro_use] extern crate lazy_static;


// TODO bug report?
#[macro_export]
macro_rules! branch {
    (if ($cond:expr) { $($a:stmt)* } else { $($b:stmt)* } then $c:expr) => (
        if $cond {
            $($a);*; $c
        } else {
            $($b);*; $c
        }
    )
}

#[macro_export]
macro_rules! delegate_arith{($stru:ident, $traitname:ident, $methname:ident, $oty:ty) => (
    impl std::ops::$traitname<$oty> for $stru {
        type Output = $stru;
        #[inline(always)]
        fn $methname(self, rhs: $oty) -> $stru {
            let $stru(a) = self;
            $stru(a.$methname(rhs))
        }
    }
    impl std::ops::$traitname<$stru> for $oty {
        type Output = $stru;
        #[inline(always)]
        fn $methname(self, $stru(rhs): $stru) -> $stru {
            $stru(self.$methname(rhs))
        }
    }
)}


#[macro_export]
macro_rules! display_as_debug{($ty:ty) => (
    impl ::std::fmt::Display for $ty {
        fn fmt(&self, fmt: &mut ::std::fmt::Formatter) -> ::std::fmt::Result  {
            ::std::fmt::Debug::fmt(self, fmt)
        }
    }
)}

#[macro_export]
macro_rules! offset_of{($ty:ty, $field:ident) => (
    unsafe { (&(*(0 as *const $ty)).$field) as *const _ as usize }
)}

#[macro_export]
macro_rules! errln {($($a:tt)*) => {{
    use ::std::io::Write;
    writeln!(::std::io::stderr(), $($a)*).unwrap();
}}}

#[macro_export]
macro_rules! some_or {($opt:expr, $els:stmt) => {
    if let Some(xxx) = $opt { xxx } else { $els }
}}
#[macro_export]
macro_rules! ok_or {($res:expr, $evar:pat, $els:stmt) => {
    match $res {
        Ok(xxx) => xxx,
        Err($evar) => { $els },
    }
}}
#[macro_export]
macro_rules! as_items { ($($i:item)*) => { $($i)* } }

#[macro_export]
macro_rules! trait_alias {(($($bounds:ident),*), $name:ident, $($based:tt)*) => {
    as_items! {
        trait $name<$($bounds),*> : $($based)* {}
        impl<$($bounds),*, Q: $($based)*> $name<$($bounds),*> for Q {}
    }
}}

#[macro_export]
macro_rules! impl_check_x_option {($trait_:ident, $meth:ident, $T:ty, $U:ty) => {
    impl $trait_<$U, $T> for Option<$T> {
        type Output = <$T as $trait_<$U, $T>>::Output;
        #[inline]
        fn $meth(self, other: $U) -> Option<Self::Output> {
            if let Some(s) = self { s.$meth(other) } else { None }
        }
    }
    impl $trait_<Option<$U>, $T> for $T {
        type Output = <$T as $trait_<$U, $T>>::Output;
        #[inline]
        fn $meth(self, other: Option<$U>) -> Option<Self::Output> {
            if let Some(o) = other { self.$meth(o) } else { None }
        }
    }
    impl $trait_<Option<$U>, $T> for Option<$T> {
        type Output = <$T as $trait_<$U, $T>>::Output;
        #[inline]
        fn $meth(self, other: Option<$U>) -> Option<Self::Output> {
            if let (Some(s), Some(o)) = (self, other) { s.$meth(o) } else { None }
        }
    }

}}

#[macro_export]
macro_rules! field_lens { ($ty:ty, $field:ident) => {
    unsafe { util::__field_lens::<$ty, _>(&(*(0 as *const $ty)).$field as *const _) }
} }

#[macro_export]
macro_rules! re { ($a:expr) => { {
    lazy_static! {
        static ref RE: ::regex::Regex = ::regex::Regex::new($a).unwrap();
    };
    &*RE
} } }

#[macro_export]
macro_rules! simple_bitflags {
    {$name:ident: $base:ty { $($a:ident/$b:ident:$c:ident<<$d:expr),* $(,)* }} => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
        struct $name { pub bits: $base }
        impl $name { $(_simple_bitflags_field!($name, $base, ($a/$b:$c<<$d));)* }
    };
    {pub $name:ident: $base:ty { $($a:ident/$b:ident:$c:ident<<$d:expr),* $(,)* }} => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
        pub struct $name { pub bits: $base }
        impl $name { $(_simple_bitflags_field!($name, $base, ($a/$b:$c<<$d));)* }
    };
}

#[macro_export]
macro_rules! _simple_bitflags_field {
    ($name:ident, $base:ty, ($getter:ident / $setter:ident : bool << $shift:expr)) => {
        #[inline]
        fn $getter(self) -> bool {
            let shift: u32 = $shift;
            (self.bits >> shift) & 1 != 0
        }
        #[inline]
        fn $setter(&mut self, val: bool) {
            let shift: u32 = $shift;
            self.bits = (self.bits & !(1 << shift)) | ((val as $base) << shift);
        }
    }
}

#[macro_export]
macro_rules! scope {
    { $lt:tt : $block:block } => {
        #[allow(unreachable_code)] {
            $lt: loop {
                #[warn(unreachable_code)] { $block; }
                break;
            }
        }
    }
}

#[test]
fn test_bitflags() {
    simple_bitflags! {
        Foo: u16 {
            one/set_one: bool << 0,
            two/set_two: bool << 1,
        }
    }
    let mut foo = Foo { bits: 0b01 };
    assert!(foo.one() == true);
    assert!(foo.two() == false);
    foo.set_one(false);
    foo.set_two(true);
    assert!(foo.bits == 0b10);

}

#[test]
fn test_scope() {
    scope! { 'foo: { break 'foo; } }

}
