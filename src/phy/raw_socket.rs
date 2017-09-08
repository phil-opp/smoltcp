use std::cell::RefCell;
use std::rc::Rc;
use std::io;
use std::os::unix::io::{RawFd, AsRawFd};
use std::vec::Vec;

use Result;
use super::{sys, DeviceLimits, RxDevice, TxDevice};

/// A socket that captures or transmits the complete frame.
#[derive(Debug)]
pub struct RawSocket {
    lower:  Rc<RefCell<sys::RawSocketDesc>>,
    mtu:    usize
}

impl AsRawFd for RawSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.lower.borrow().as_raw_fd()
    }
}

impl RawSocket {
    /// Creates a raw socket, bound to the interface called `name`.
    ///
    /// This requires superuser privileges or a corresponding capability bit
    /// set on the executable.
    pub fn new(name: &str) -> io::Result<RawSocket> {
        let mut lower = sys::RawSocketDesc::new(name)?;
        lower.bind_interface()?;
        let mtu = lower.interface_mtu()?;
        Ok(RawSocket {
            lower: Rc::new(RefCell::new(lower)),
            mtu:   mtu
        })
    }
}

impl RxDevice for RawSocket {
    type RxBuffer = Vec<u8>;

    fn receive<T, F>(&mut self, _timestamp: u64, f: F) -> Result<T>
    where
        F: FnOnce(Self::RxBuffer) -> Result<T>,
    {
        let mut lower = self.lower.borrow_mut();
        let mut buffer = vec![0; self.mtu];
        let size = lower.recv(&mut buffer[..]).unwrap();
        buffer.resize(size, 0);
        f(buffer)
    }
}

impl TxDevice for RawSocket {
    fn limits(&self) -> DeviceLimits {
        DeviceLimits {
            max_transmission_unit: self.mtu,
            ..DeviceLimits::default()
        }
    }

    fn transmit<F>(&mut self, _timestamp: u64, length: usize, f: F) -> Result<()>
        where F: FnOnce(&mut [u8]) -> Result<()>
    {
        let mut buffer = vec![0; length];
        f(&mut buffer)?;
        self.lower.borrow_mut().send(&buffer).unwrap();
        Ok(())
    }
}
