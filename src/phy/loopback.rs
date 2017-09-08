use core::cell::RefCell;
#[cfg(feature = "std")]
use std::rc::Rc;
#[cfg(feature = "alloc")]
use alloc::rc::Rc;
#[cfg(feature = "std")]
use std::vec::Vec;
#[cfg(feature = "std")]
use std::collections::VecDeque;
#[cfg(feature = "alloc")]
use alloc::{Vec, VecDeque};

use {Error, Result};
use super::{RxDevice, TxDevice, DeviceLimits};

/// A loopback device.
#[derive(Debug)]
pub struct Loopback(Rc<RefCell<VecDeque<Vec<u8>>>>);

impl Loopback {
    /// Creates a loopback device.
    ///
    /// Every packet transmitted through this device will be received through it
    /// in FIFO order.
    pub fn new() -> Loopback {
        Loopback(Rc::new(RefCell::new(VecDeque::new())))
    }
}

impl RxDevice for Loopback {
    fn receive<T, F>(&mut self, _timestamp: u64, f: F) -> Result<T>
    where
        F: FnOnce(&[u8]) -> Result<T>,
    {
        match self.0.borrow_mut().pop_front() {
            Some(packet) => f(&packet),
            None => Err(Error::Exhausted)
        }
    }
}

impl TxDevice for Loopback {
    fn limits(&self) -> DeviceLimits {
        DeviceLimits {
            max_transmission_unit: 65535,
            ..DeviceLimits::default()
        }
    }

    fn transmit<F>(&mut self, _timestamp: u64, length: usize, f: F) -> Result<()>
        where F: FnOnce(&mut [u8]) -> Result<()>
    {
        let mut buffer = Vec::new();
        buffer.resize(length, 0);
        f(&mut buffer)?;
        self.0.borrow_mut().push_back(buffer);
        Ok(())
    }
}
