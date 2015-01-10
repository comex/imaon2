// The usage could be prettier as an attribute / syntax extension, but this is drastically less ugly.
// TODO: Servo has similar ugliness with GC visits.  Use their solution.
#[macro_export]
macro_rules! deriving_swap {
    (
        $(twin $twin:ident)*
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
        impl Default for $name {
            fn default() -> $name {
                unsafe { zeroed_t() }
            }
        }
        $($etc)*
    )
}

#[macro_export]
macro_rules! branch {
    (if $cond:expr { $($a:stmt)* } else { $($b:stmt)* } then $c:expr) => (
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
)}


#[macro_export]
macro_rules! string_as_show{($ty:ty) => (
    impl ::std::fmt::String for $ty {
        fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result  {
            ::std::fmt::Show::fmt(self, fmt)
        }
    }
)}
