use std::alloc::{alloc, dealloc, Layout};

// @flag --check=memory-safety
// @expect error

fn main() {
    let layout = Layout::new::<u32>();
    unsafe {
	let x = alloc(layout);
	dealloc(x, layout);
	dealloc(x, layout);
    }
}
