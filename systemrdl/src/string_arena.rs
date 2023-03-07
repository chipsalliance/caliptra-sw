// Licensed under the Apache-2.0 license

use std::collections::HashSet;

// TODO: Consider using elsa/FrozenVec to remove unsafe code
#[derive(Default)]
pub struct StringArena {
    // SAFETY: To maintain soundness, strings in this HashSet MUST NOT be removed or mutated.
    strings: std::cell::RefCell<HashSet<String>>,
}
impl StringArena {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Default::default()
    }
    pub fn add<'a>(&'a self, s: String) -> &'a str {
        let mut map = self.strings.borrow_mut();
        if let Some(existing) = map.get(&s) {
            unsafe { std::mem::transmute::<&'_ str, &'a str>(existing.as_str()) }
        } else {
            let slice = unsafe { std::mem::transmute::<&'_ str, &'a str>(s.as_str()) };
            map.insert(s);
            slice
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn foo() {
        let arena = StringArena::new();
        let a = arena.add("Hello world".into());
        let b = arena.add("Foo".into());
        let c = arena.add("Foo".into());
        assert_eq!(a, "Hello world");
        assert_eq!(b, "Foo");
        assert_eq!(c, "Foo");
        assert_eq!(b.as_ptr(), c.as_ptr());
        drop(arena);
    }
}
