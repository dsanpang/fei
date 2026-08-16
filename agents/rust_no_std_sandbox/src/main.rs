#![no_std]
#![no_main]

extern crate alloc;
extern crate fei_agent_sandbox;

use core::panic::PanicInfo;
use core::alloc::{GlobalAlloc, Layout};
use core::sync::atomic::{AtomicUsize, Ordering};

const HEAP_SIZE: usize = 4 * 1024 * 1024; // 4MB bump heap (process_list retry buffers need ~2MB)

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
fn panic(info: &PanicInfo) -> ! {
    // surface the panic on the pipe, then terminate (never spin: the old
    // handler burned a full core forever on heap exhaustion)
    unsafe {
        let (_, stdout) = fei_agent_sandbox::debug_std_handles();
        fei_agent_sandbox::debug_write(stdout, b"
[[PANIC]]
");
        // best effort: include the payload location if present
        if let Some(loc) = info.location() {
            let mut line = [b'0'; 8];
            let mut n = loc.line();
            let mut i = 8;
            while n > 0 && i > 0 {
                i -= 1;
                line[i] = b'0' + (n % 10) as u8;
                n /= 10;
            }
            fei_agent_sandbox::debug_write(stdout, b"line:");
            fei_agent_sandbox::debug_write(stdout, &line[i..]);
        }
    }
    fei_agent_sandbox::exit_process(0xC0000409u32 as i32)
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    unsafe {
        ALLOCATOR.init(HEAP.as_ptr() as usize, HEAP_SIZE);
    }

    fei_agent_sandbox::run();

    fei_agent_sandbox::exit_process(0)
}
