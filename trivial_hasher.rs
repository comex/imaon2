use std::hash::{Hasher, BuildHasher};
pub struct TrivialState;
pub struct TrivialHasher { num_writes: usize, val: u64 }

impl Hasher for TrivialHasher {
    #[inline]
    fn finish(&self) -> u64 {
        if self.num_writes != 1 {
            panic!("TrivialHasher wasn't used trivially (too many writes)");
        }
        self.val
    }

    fn write(&mut self, _bytes: &[u8]) {
        panic!("TrivialHasher wasn't used trivially (non-integral data)");
    }

    #[inline]
    fn write_u8(&mut self, i: u8) {
        self.val = i as u64;
        self.num_writes += 1;
    }
    #[inline]
    fn write_u16(&mut self, i: u16) {
        self.val = i as u64;
        self.num_writes += 1;
    }
    #[inline]
    fn write_u32(&mut self, i: u32) {
        self.val = i as u64;
        self.num_writes += 1;
    }
    #[inline]
    fn write_u64(&mut self, i: u64) {
        self.val = i as u64;
        self.num_writes += 1;
    }
    #[inline]
    fn write_usize(&mut self, i: usize) {
        self.val = i as u64;
        self.num_writes += 1;
    }

    #[inline]
    fn write_i8(&mut self, i: i8) {
        self.val = i as u64;
        self.num_writes += 1;
    }
    #[inline]
    fn write_i16(&mut self, i: i16) {
        self.val = i as u64;
        self.num_writes += 1;
    }
    #[inline]
    fn write_i32(&mut self, i: i32) {
        self.val = i as u64;
        self.num_writes += 1;
    }
    #[inline]
    fn write_i64(&mut self, i: i64) {
        self.val = i as u64;
        self.num_writes += 1;
    }
    #[inline]
    fn write_isize(&mut self, i: isize) {
        self.val = i as u64;
        self.num_writes += 1;
    }
}

impl BuildHasher for TrivialState {
    type Hasher = TrivialHasher;
    #[inline]
    fn build_hasher(&self) -> TrivialHasher {
        TrivialHasher { num_writes: 0, val: 0 }
    }
}

#[test]
fn test_it() {
    use std::collections::HashMap;
    let mut foo = HashMap::with_hasher(TrivialState);
    foo.insert(2, 3);
    foo.insert(4, 5);
    foo.insert(2000, 7);
    assert_eq!(foo[&2], 3);
    assert_eq!(foo[&4], 5);
    assert_eq!(foo[&2000], 7);
}
