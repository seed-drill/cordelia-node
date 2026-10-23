//! What a thread holds, counted by an allocator that counts for each
//! thread: the bytes asked for and not given back. The allocator of this
//! binary's tests, so that a test can tell what a task holds while it
//! waits on a stream (parameter-rationale.md §1).

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

pub struct Counting;

thread_local! {
    static LIVE: Cell<isize> = const { Cell::new(0) };
}

fn counted(bytes: isize) {
    let _ = LIVE.try_with(|live| live.set(live.get() + bytes));
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let at = unsafe { System.alloc(layout) };
        if !at.is_null() {
            counted(layout.size() as isize);
        }
        at
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let at = unsafe { System.alloc_zeroed(layout) };
        if !at.is_null() {
            counted(layout.size() as isize);
        }
        at
    }

    unsafe fn dealloc(&self, at: *mut u8, layout: Layout) {
        unsafe { System.dealloc(at, layout) };
        counted(-(layout.size() as isize));
    }

    unsafe fn realloc(&self, at: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let moved = unsafe { System.realloc(at, layout, size) };
        if !moved.is_null() {
            counted(size as isize - layout.size() as isize);
        }
        moved
    }
}

#[global_allocator]
static COUNTING: Counting = Counting;

/// The bytes this thread holds.
pub fn live() -> isize {
    LIVE.with(Cell::get)
}
