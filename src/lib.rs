
extern crate libc;

type NfctHandle = *const libc::c_void;

#[link(name = "netfilter_conntrack")]
extern {
    // library setup
    fn nfct_open() -> NfctHandle;
    fn nfct_close(cth: NfctHandle);

    // connection handling
    //fn nfct_setobjopt
    //fn nfct_getobjopt
    //fn nfct_callback_register
    //fn nfct_callback_unregister
}

/// Conntrack object
pub struct Conntrack<T> {
    cth : NfctHandle,
    data: T,
}

impl <T: Send> Conntrack<T> {

    /// Creates a new Conntrack
    pub fn new(data: T) -> Conntrack<T> {
        return Conntrack {
            cth : std::ptr::null_mut(),
            data: data,
        };
    }

    pub fn open(&mut self) {
        self.cth = unsafe { nfct_open() };
    }

    pub fn close(&mut self) {
        assert!(!self.cth.is_null());
        unsafe { nfct_close(self.cth) };
        self.cth = std::ptr::null_mut();
    }
}

#[cfg(test)]
mod tests {

    extern crate libc;

    #[test]
    fn nfconntrack_open() {
        let mut ct = ::Conntrack::new(());

        ct.open();

        let raw = ct.cth as *const i32;
        println!("nfct_open: 0x{:x}", unsafe{*raw});

        assert!(!ct.cth.is_null());

        ct.close();
    }
}