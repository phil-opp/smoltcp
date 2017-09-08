use Result;
use wire::pretty_print::{PrettyPrint, PrettyPrinter};
use super::{DeviceLimits, RxDevice, TxDevice};

/// A tracer device.
///
/// A tracer is a device that pretty prints all packets traversing it
/// using the provided writer function, and then passes them to another
/// device.
pub struct Tracer<D, P: PrettyPrint> {
    inner:     D,
    writer:    fn(u64, PrettyPrinter<P>)
}

impl<D, P: PrettyPrint> Tracer<D, P> {
    /// Create a tracer device.
    pub fn new(inner: D, writer: fn(timestamp: u64, printer: PrettyPrinter<P>)) -> Self {
        Tracer { inner, writer }
    }

    /// Return the underlying device, consuming the tracer.
    pub fn inner(self) -> D {
        self.inner
    }
}

impl<D: RxDevice, P: PrettyPrint> RxDevice for Tracer<D, P> {
    fn receive<T, F>(&mut self, timestamp: u64, f: F) -> Result<T>
    where
        F: FnOnce(&[u8]) -> Result<T>,
    {
        let &mut Self {ref mut inner, ref mut writer} = self;
        let f = |buffer: &[u8]| {
            writer(timestamp, PrettyPrinter::<P>::new("<- ", buffer));
            f(buffer)
        };
        let buffer = inner.receive(timestamp, f)?;
        Ok(buffer)
    }
}

impl<D: TxDevice, P: PrettyPrint> TxDevice for Tracer<D, P> {
    fn limits(&self) -> DeviceLimits { self.inner.limits() }

    fn transmit<F>(&mut self, timestamp: u64, length: usize, f: F) -> Result<()>
        where F: FnOnce(&mut [u8]) -> Result<()>
    {
        let &mut Self {ref mut inner, ref mut writer} = self;
        inner.transmit(timestamp, length, |buffer| {
            writer(timestamp, PrettyPrinter::<P>::new("-> ", &buffer));
            f(buffer)
        })
    }
}
