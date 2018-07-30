use winapi::shared::ntdef::{HANDLE, NULL};
use winapi::um::handleapi::{INVALID_HANDLE_VALUE, CloseHandle};

pub struct HandlePtr {
    pub raw: HANDLE,
}

impl HandlePtr {
    pub fn new(ptr: HANDLE) -> HandlePtr {
        HandlePtr { raw: ptr}
    }
}

impl Drop for HandlePtr {
    fn drop(&mut self) {
        if self.raw != NULL && self.raw != INVALID_HANDLE_VALUE {
            unsafe { CloseHandle(self.raw) };
            self.raw = INVALID_HANDLE_VALUE;
        }
    }
}