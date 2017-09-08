use std::cell::RefCell;
use std::rc::Rc;
use std::io;
use std::os::unix::io::{RawFd, AsRawFd};

use {Error, Result};
use super::{sys, DeviceLimits, RxDevice, TxDevice};

/// A virtual Ethernet interface.
#[derive(Debug)]
pub struct TapInterface {
    lower:  Rc<RefCell<sys::TapInterfaceDesc>>,
    mtu:    usize
}

impl AsRawFd for TapInterface {
    fn as_raw_fd(&self) -> RawFd {
        self.lower.borrow().as_raw_fd()
    }
}

impl TapInterface {
    /// Attaches to a TAP interface called `name`, or creates it if it does not exist.
    ///
    /// If `name` is a persistent interface configured with UID of the current user,
    /// no special privileges are needed. Otherwise, this requires superuser privileges
    /// or a corresponding capability set on the executable.
    pub fn new(name: &str) -> io::Result<TapInterface> {
        let mut lower = sys::TapInterfaceDesc::new(name)?;
        lower.attach_interface()?;
        let mtu = lower.interface_mtu()?;
        Ok(TapInterface {
            lower: Rc::new(RefCell::new(lower)),
            mtu:   mtu
        })
    }
}

impl RxDevice for TapInterface {
    fn receive<T, F>(&mut self, _timestamp: u64, f: F) -> Result<T>
    where
        F: FnOnce(&[u8]) -> Result<T>,
    {
        let mut lower = self.lower.borrow_mut();
        let mut buffer = vec![0; self.mtu];
        match lower.recv(&mut buffer[..]) {
            Ok(size) => {
                buffer.resize(size, 0);
                f(&buffer)
            }
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {
                Err(Error::Exhausted)
            }
            Err(err) => panic!("{}", err)
        }
    }
}

impl TxDevice for TapInterface {
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
        self.lower.borrow_mut().send(&mut buffer[..]).unwrap();
        Ok(())
    }
}
