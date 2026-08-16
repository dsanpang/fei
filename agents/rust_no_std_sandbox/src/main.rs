#![no_std]
#![no_main]

extern crate alloc;
extern crate fei_agent_sandbox;

use core::panic::PanicInfo;
use core::alloc::{GlobalAlloc, Layout};
use core::sync::atomic::{AtomicUsize, Ordering};

const HEAP_SIZE: usize = 1024 * 1024; // 1MB static heap

struct BumpAllocator {
    heap_start: usize,
    heap_end: usize,
    next: AtomicUsize,
}

impl BumpAllocator {
    const fn new() -> Self {
        Self {
            heap_start: 0,
            heap_end: 0,
            next: AtomicUsize::new(0),
        }
    }

    fn init(&self, heap_start: usize, heap_size: usize) {
        self.next.store(heap_start, Ordering::SeqCst);
        unsafe {
            let self_mut = self as *const Self as *mut Self;
            (*self_mut).heap_start = heap_start;
            (*self_mut).heap_end = heap_start + heap_size;
        }
    }
}

unsafe impl GlobalAlloc for BumpAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let size = layout.size();
        let align = layout.align();

        loop {
            let current = self.next.load(Ordering::Relaxed);
            let aligned = (current + align - 1) & !(align - 1);
            let new_next = aligned + size;

            if new_next > self.heap_end {
                return core::ptr::null_mut();
            }

            if self.next.compare_exchange(current, new_next, Ordering::SeqCst, Ordering::Relaxed).is_ok() {
                return aligned as *mut u8;
            }
        }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
        // Bump allocator: freed only when the process exits
    }
}

#[global_allocator]
static ALLOCATOR: BumpAllocator = BumpAllocator::new();

static mut HEAP: [u8; HEAP_SIZE] = [0; HEAP_SIZE];

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    unsafe {
        ALLOCATOR.init(HEAP.as_ptr() as usize, HEAP_SIZE);
    }

    fei_agent_sandbox::run();

    // NtTerminateProcess(NULL, 0): clean no_std exit, no CRT and no PEB walk
    unsafe {
        core::arch::asm!(
            "mov r10, rcx",
            "syscall",
            in("rax") 0x2Cu64,
            in("rcx") 0usize,
            in("rdx") 0u32,
            options(nomem, nostack)
        );
    }
    loop {}
}
