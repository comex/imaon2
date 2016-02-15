// The usage could be prettier as an attribute / syntax extension, but this is drastically less ugly.
// TODO: Servo has similar ugliness with GC visits.  Use their solution.
#[macro_export]

macro_rules! deriving_swap {
    (
        //$(twin $twin:ident)*
        #[repr(C)]
        #[derive(Copy)]
        pub struct $name:ident {
            $(
                pub $field:ident: $typ:ty
            ),+
            $(,)*
        }
        $($etc:item)*
    ) => (
        #[repr(C)]
        #[derive(Copy)]
        pub struct $name {
            $(
                pub $field: $typ
            ),+
        }
        impl Swap for $name {
            fn bswap(&mut self) {
                $(
                    self.$field.bswap();
                )+
            }
        }
        $($etc)*
    )
}

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
        fn $methname(self, rhs: $oty) -> $stru {
            let $stru(a) = self;
            $stru(a.$methname(rhs))
        }
    }
    impl std::ops::$traitname<$stru> for $oty {
        type Output = $stru;
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
    if let Some(xxx) = $opt { xxx } else { $els; }
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
