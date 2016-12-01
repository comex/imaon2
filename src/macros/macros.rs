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
