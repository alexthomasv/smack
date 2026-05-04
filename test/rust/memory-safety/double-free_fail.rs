use std::alloc::{alloc, Layout, System};
use std::ptr;

// @skip

struct S {
    data: &i32,
}

fn main() {
    let layout = Layout::new::<i32>();
    let x = S { data: alloc(layout) as *const i32 };
    let y = unsafe { ptr::read(x) };
    
}
