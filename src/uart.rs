//! UART driver module

use core::fmt::{Error, Write};

/// UART base address on QEMU RISC-V
pub const UART_BASE_ADDR: usize = 0x1000_0000;

pub struct Uart {
    base_address: usize,
}

impl Uart {
    pub fn new(base_address: usize) -> Self {
        Uart { base_address }
    }

    /// Initialize UART driver
    pub fn init(&mut self) {
        let ptr = self.base_address as *mut u8;

        unsafe {
            // Set word length to 8-bits (LCR[1:0])
            ptr.add(3).write_volatile((1 << 0) | (1 << 1));

            // Enable FIFOs (FCR[0])
            ptr.add(2).write_volatile(1 << 0);

            // Enable receiver interrupts (IER[0])
            ptr.add(1).write_volatile(1 << 0);

            // Set the divisor from a global clock rate
            // of 22.729 MHz (22,729,000 cycles per second)
            // to a signaling rate of 2400 (BAUD)
            let divisor: u16 = 592;
            let divisor_least: u8 = (divisor & 0xff) as u8;
            let divisor_most: u8 = (divisor >> 8) as u8;

            // Set DLAB to 1
            let lcr = ptr.add(3).read_volatile();
            ptr.add(3).write_volatile(lcr | 1 << 7);

            // Set DLL & DLM
            ptr.add(0).write_volatile(divisor_least);
            ptr.add(1).write_volatile(divisor_most);

            // Set DLAB back to 0
            ptr.add(3).write_volatile(lcr);
        }
    }

    /// Put a character into UART
    pub fn put(&mut self, c: u8) {
        let ptr = self.base_address as *mut u8;
        unsafe {
            ptr.write_volatile(c);
        }
    }

    /// Get a character from UART
    pub fn get(&self) -> Option<u8> {
        let ptr = self.base_address as *mut u8;
        unsafe {
            if ptr.add(5).read_volatile() & 1 == 0 {
                // The DR bit is 0, meaning no data
                None
            } else {
                // The DR bit is 1, meaning data!
                Some(ptr.read_volatile())
            }
        }
    }
}

impl Write for Uart {
    fn write_str(&mut self, out: &str) -> Result<(), Error> {
        for c in out.bytes() {
            self.put(c);
        }
        Ok(())
    }
}
