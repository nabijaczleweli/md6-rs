//! An implementation of the [MD6 hash function](http://groups.csail.mit.edu/cis/md6), via FFI to reference implementation.
//!
//! For more information about MD6 visit its [official homepage](http://groups.csail.mit.edu/cis/md6).
//!
//! There are two APIs provided: one for single-chunk hashing and one for hashing of multiple data segments.
//!
//! # Examples
//!
//! Hashing a single chunk of data with a 256-bit MD6 hash function, then verifying the result.
//!
//! ```
//! # use md6::Md6;
//! # use std::iter::FromIterator;
//! let mut result = [0; 32];
//! md6::hash(256, b"The lazy fox jumps over the lazy dog", &mut result).unwrap();
//!
//! assert_eq!(Vec::from_iter(result.iter().map(|&i| i)),
//!            vec![0xE4, 0x55, 0x51, 0xAA, 0xE2, 0x66, 0xE1, 0x48,
//!                 0x2A, 0xC9, 0x8E, 0x24, 0x22, 0x9B, 0x3E, 0x90,
//!                 0xDC, 0x06, 0x61, 0x77, 0xF8, 0xFB, 0x1A, 0x52,
//!                 0x6E, 0x9D, 0xA2, 0xCC, 0x95, 0x71, 0x97, 0xAA]);
//! ```
//!
//! Hashing multiple chunks of data with a 512-bit MD6 hash function, then verifying the result.
//!
//! ```
//! # use md6::Md6;
//! # use std::iter::FromIterator;
//! let mut result = [0; 64];
//! let mut state = Md6::new(512).unwrap();
//!
//! state.update("Zażółć ".as_bytes());
//! state.update("gęślą ".as_bytes());
//! state.update("jaźń".as_bytes());
//!
//! state.finalise(&mut result);
//! assert_eq!(Vec::from_iter(result.iter().map(|&i| i)),
//!            vec![0x92, 0x4E, 0x91, 0x6A, 0x01, 0x2C, 0x1A, 0x8D,
//!                 0x0F, 0xB7, 0x9A, 0x4A, 0xD4, 0x9C, 0x55, 0x5E,
//!                 0xBD, 0xCA, 0x59, 0xB8, 0x1B, 0x4C, 0x13, 0x41,
//!                 0x2E, 0x32, 0xA5, 0xC9, 0x3B, 0x61, 0xAD, 0xB8,
//!                 0x4D, 0xB3, 0xF9, 0x0C, 0x03, 0x51, 0xB2, 0x9E,
//!                 0x7B, 0xAE, 0x46, 0x9F, 0x8D, 0x60, 0x5D, 0xED,
//!                 0xFF, 0x51, 0x72, 0xDE, 0xA1, 0x6F, 0x00, 0xF7,
//!                 0xB4, 0x82, 0xEF, 0x87, 0xED, 0x77, 0xD9, 0x1A]);
//! ```
//!
//! Comparing result of single- and multi-chunk hash methods hashing the same effective message with a 64-bit MD6 hash
//! function.
//!
//! ```
//! # use md6::Md6;
//! # use std::iter::FromIterator;
//! let mut result_multi  = [0; 8];
//! let mut result_single = [0; 8];
//!
//! let mut state = Md6::new(64).unwrap();
//! state.update("Zażółć ".as_bytes());
//! state.update("gęślą ".as_bytes());
//! state.update("jaźń".as_bytes());
//! state.finalise(&mut result_multi);
//!
//! md6::hash(64, "Zażółć gęślą jaźń".as_bytes(), &mut result_single).unwrap();
//!
//! assert_eq!(Vec::from_iter(result_multi .iter().map(|&i| i)),
//!            Vec::from_iter(result_single.iter().map(|&i| i)));
//! ```
//!
//! # Special thanks
//!
//! To all who support further development on [Patreon](https://patreon.com/nabijaczleweli), in particular:
//!
//!   * ThePhD

extern crate libc;

mod native;

use std::error::Error;
use std::fmt;
use std::io;


/// Helper result type containing `Md6Error`.
pub type Result<T> = std::result::Result<T, Md6Error>;


/// Hash all data in one fell swoop.
///
/// Refer to individual functions for extended documentation.
///
/// # Example
///
/// ```
/// # use md6::Md6;
/// # use std::iter::FromIterator;
/// let mut result_256 = [0; 32];
/// let mut result_512 = [0; 64];
///
/// md6::hash(256, &[], &mut result_256).unwrap();
/// md6::hash(512, &[], &mut result_512).unwrap();
///
/// assert_eq!(Vec::from_iter(result_256.iter().map(|&i| i)),
///            vec![0xBC, 0xA3, 0x8B, 0x24, 0xA8, 0x04, 0xAA, 0x37,
///                 0xD8, 0x21, 0xD3, 0x1A, 0xF0, 0x0F, 0x55, 0x98,
///                 0x23, 0x01, 0x22, 0xC5, 0xBB, 0xFC, 0x4C, 0x4A,
///                 0xD5, 0xED, 0x40, 0xE4, 0x25, 0x8F, 0x04, 0xCA]);
/// assert_eq!(Vec::from_iter(result_512.iter().map(|&i| i)),
///            vec![0x6B, 0x7F, 0x33, 0x82, 0x1A, 0x2C, 0x06, 0x0E,
///                 0xCD, 0xD8, 0x1A, 0xEF, 0xDD, 0xEA, 0x2F, 0xD3,
///                 0xC4, 0x72, 0x02, 0x70, 0xE1, 0x86, 0x54, 0xF4,
///                 0xCB, 0x08, 0xEC, 0xE4, 0x9C, 0xCB, 0x46, 0x9F,
///                 0x8B, 0xEE, 0xEE, 0x7C, 0x83, 0x12, 0x06, 0xBD,
///                 0x57, 0x7F, 0x9F, 0x26, 0x30, 0xD9, 0x17, 0x79,
///                 0x79, 0x20, 0x3A, 0x94, 0x89, 0xE4, 0x7E, 0x04,
///                 0xDF, 0x4E, 0x6D, 0xEA, 0xA0, 0xF8, 0xE0, 0xC0]);
/// ```
pub fn hash(hashbitlen: i32, data: &[u8], hashval: &mut [u8]) -> Result<()> {
    match unsafe { native::MD6_Hash_Hash(hashbitlen, data.as_ptr(), data.len() as u64 * 8, hashval.as_mut_ptr()) } {
        0 => Ok(()),
        e => Err(Md6Error::from(e)),
    }
}

/// Hashing state for multiple data sets.
///
/// # Example
///
/// Hashing a string split into multiple chunks.
///
/// ```
/// # use md6::Md6;
/// # use std::iter::FromIterator;
/// let mut state = Md6::new(256).unwrap();
///
/// state.update(b"Abolish ");
/// state.update(b"the ");
/// state.update(b"bourgeoisie");
/// state.update(b"!");
///
/// let mut result = [0; 32];
/// state.finalise(&mut result);
/// assert_eq!(Vec::from_iter(result.iter().map(|&i| i)),
///            vec![0x49, 0x23, 0xE7, 0xB0, 0x53, 0x32, 0x05, 0xB0,
///                 0x25, 0xC5, 0xD4, 0xDB, 0x37, 0xB8, 0x99, 0x12,
///                 0x16, 0x2E, 0xFD, 0xF4, 0xDA, 0xC2, 0x2C, 0xFF,
///                 0xE6, 0x27, 0xF1, 0x11, 0xEC, 0x05, 0x2F, 0xB5]);
/// ```
///
/// A `Write` implementation is also provided:
///
/// ```
/// # use std::iter::FromIterator;
/// # use md6::Md6;
/// # use std::io;
/// let mut state = Md6::new(256).unwrap();
/// io::copy(&mut &b"The lazy fox jumps over the lazy dog."[..], &mut state).unwrap();
///
/// let mut result = [0; 32];
/// state.finalise(&mut result);
/// assert_eq!(Vec::from_iter(result.iter().map(|&i| i)),
///            vec![0x06, 0x60, 0xBB, 0x89, 0x85, 0x06, 0xE4, 0xD9,
///                 0x29, 0x8C, 0xD1, 0xB0, 0x40, 0x73, 0x49, 0x60,
///                 0x47, 0x3E, 0x25, 0xA4, 0x9D, 0x52, 0x34, 0xBB,
///                 0x2A, 0xCA, 0x31, 0x57, 0xD1, 0xAF, 0x27, 0xAA]);
/// ```
pub struct Md6 {
    raw_state: native::FFIHashState,
}

/// Some functions in the library can fail, this enum represents all the possible ways they can.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub enum Md6Error {
    /// Generic failure state
    Fail,
    /// `hashbitlen` passed to `Md6::new()` or `hash()` incorrect
    BadHashbitlen,
}


impl Md6 {
    /// Create a new hash state and initialise it with the given bit length.
    ///
    /// `hashbitlen` is the hash output length. Must be between `1` and `512`.
    ///
    /// Returns:
    ///
    ///   * `Err(Md6Error::BadHashbitlen)` if `hashbitlen` is not any of the mentioned above, or
    ///   * `Ok(Md6)` if initialisation succeeds.
    ///
    /// # Examples
    ///
    /// Incorrect `hashbitlen`
    ///
    /// ```
    /// # use md6::Md6;
    /// assert_eq!(Md6::new(0).map(|_| ()), Err(md6::Md6Error::BadHashbitlen));
    /// assert_eq!(Md6::new(1024).map(|_| ()), Err(md6::Md6Error::BadHashbitlen));
    /// ```
    ///
    /// Creating a 512-long state
    ///
    /// ```
    /// # use md6::Md6;
    /// Md6::new(512).unwrap();
    /// ```
    pub fn new(hashbitlen: i32) -> Result<Md6> {
        let mut raw_state = native::malloc_hash_state();

        match unsafe { native::MD6_Hash_Init(raw_state, hashbitlen) } {
            0 => Ok(Md6 { raw_state: raw_state }),
            e => {
                native::free_hash_state(&mut raw_state);
                Err(Md6Error::from(e))
            }
        }
    }

    /// Append the provided data to the hash function.
    ///
    /// # Examples
    ///
    /// Hashing a part of [a short story](http://nabijaczleweli.xyz/capitalism/writing/Świat_to_kilka_takich_pokoi/)
    ///
    /// ```
    /// # use md6::Md6;
    /// # use std::iter::FromIterator;
    /// let mut result = [0; 64];
    ///
    /// let mut state = Md6::new(512).unwrap();
    /// state.update("    Serbiańcy znowu się pochlali, ale w sumie".as_bytes());
    /// state.update("czegoż się po wschodnich słowianach spodziewać, swoją".as_bytes());
    /// state.update("drogą. I, jak to wszystkim homo sapiensom się dzieje".as_bytes());
    /// state.update("filozofować poczęli.".as_bytes());
    /// state.finalise(&mut result);
    ///
    /// assert_eq!(Vec::from_iter(result.iter().map(|&i| i)),
    ///            vec![0xD4, 0xAC, 0x5B, 0xDA, 0x95, 0x44, 0xCC, 0x3F,
    ///                 0xFB, 0x59, 0x4B, 0x62, 0x84, 0xEF, 0x07, 0xDD,
    ///                 0x59, 0xE7, 0x94, 0x2D, 0xCA, 0xCA, 0x07, 0x52,
    ///                 0x14, 0x13, 0xE8, 0x06, 0xBD, 0x84, 0xB8, 0xC7,
    ///                 0x8F, 0xB8, 0x03, 0x24, 0x39, 0xC8, 0x2E, 0xEC,
    ///                 0x9F, 0x7F, 0x4F, 0xDA, 0xF8, 0x8A, 0x4B, 0x5F,
    ///                 0x9D, 0xF8, 0xFD, 0x47, 0x0C, 0x4F, 0x2F, 0x4B,
    ///                 0xCD, 0xDF, 0xAF, 0x13, 0xE1, 0xE1, 0x4D, 0x9D]);
    /// ```
    pub fn update(&mut self, data: &[u8]) {
        unsafe {
            native::MD6_Hash_Update(self.raw_state, data.as_ptr(), data.len() as u64 * 8);
        }
    }


    /// Finish hashing and store the output result in the provided space.
    ///
    /// The provided space must not be smaller than the hash function's size,
    /// if the provided space is smaller than the hash function's size, the behaviour is undefined.
    ///
    /// # Examples
    ///
    /// Storing and verifying results of all possible sizes.
    ///
    /// ```
    /// # use md6::Md6;
    /// # use std::iter::FromIterator;
    /// let mut result_64  = [0; 8];
    /// let mut result_128 = [0; 16];
    /// let mut result_256 = [0; 32];
    /// let mut result_512 = [0; 64];
    ///
    /// let mut state_64  = Md6::new(64) .unwrap();
    /// let mut state_128 = Md6::new(128).unwrap();
    /// let mut state_256 = Md6::new(256).unwrap();
    /// let mut state_512 = Md6::new(512).unwrap();
    ///
    /// state_64 .update(b"The lazy fox jumps over the lazy dog.");
    /// state_128.update(b"The lazy fox jumps over the lazy dog.");
    /// state_256.update(b"The lazy fox jumps over the lazy dog.");
    /// state_512.update(b"The lazy fox jumps over the lazy dog.");
    ///
    /// state_64 .finalise(&mut result_64);
    /// state_128.finalise(&mut result_128);
    /// state_256.finalise(&mut result_256);
    /// state_512.finalise(&mut result_512);
    ///
    /// assert_eq!(Vec::from_iter(result_64.iter().map(|&i| i)),
    ///            vec![0xF3, 0x50, 0x60, 0xAE, 0xD7, 0xF0, 0xB0, 0x96]);
    /// assert_eq!(Vec::from_iter(result_128.iter().map(|&i| i)),
    ///            vec![0x08, 0x5E, 0xA5, 0xF6, 0x6D, 0x2A, 0xC1, 0xF3,
    ///                 0xCF, 0xC5, 0x6F, 0xA3, 0x7D, 0x1B, 0xEC, 0x9C]);
    /// assert_eq!(Vec::from_iter(result_256.iter().map(|&i| i)),
    ///            vec![0x06, 0x60, 0xBB, 0x89, 0x85, 0x06, 0xE4, 0xD9,
    ///                 0x29, 0x8C, 0xD1, 0xB0, 0x40, 0x73, 0x49, 0x60,
    ///                 0x47, 0x3E, 0x25, 0xA4, 0x9D, 0x52, 0x34, 0xBB,
    ///                 0x2A, 0xCA, 0x31, 0x57, 0xD1, 0xAF, 0x27, 0xAA]);
    /// assert_eq!(Vec::from_iter(result_512.iter().map(|&i| i)),
    ///            vec![0xA5, 0xFE, 0xC7, 0x36, 0x81, 0xFA, 0x64, 0xBE,
    ///                 0xE7, 0x2D, 0xB6, 0x05, 0x35, 0x26, 0x6C, 0x00,
    ///                 0x6B, 0x2A, 0x49, 0x54, 0x04, 0x7E, 0x39, 0x05,
    ///                 0xD1, 0xFE, 0xB3, 0x25, 0x21, 0x01, 0x81, 0x2D,
    ///                 0xF2, 0x20, 0xC9, 0x09, 0xD4, 0xD7, 0xB7, 0x94,
    ///                 0x53, 0xB4, 0x2D, 0xAD, 0x6D, 0x75, 0x52, 0xC7,
    ///                 0x82, 0xE8, 0x4E, 0xFC, 0x3C, 0x34, 0x5B, 0x0C,
    ///                 0xFF, 0x72, 0x1B, 0x56, 0x73, 0x05, 0x6B, 0x75]);
    /// ```
    pub fn finalise(&mut self, hashval: &mut [u8]) {
        unsafe {
            native::MD6_Hash_Final(self.raw_state, hashval.as_mut_ptr());
        }
    }
}

/// The `Write` implementation updates the state with the provided data.
///
/// For example, to hash a file:
///
/// ```
/// # use std::iter::FromIterator;
/// # use std::fs::File;
/// # use md6::Md6;
/// # use std::io;
/// let mut state = Md6::new(256).unwrap();
/// io::copy(&mut File::open("LICENSE").unwrap(), &mut state).unwrap();
///
/// let mut result = [0; 32];
/// state.finalise(&mut result);
/// assert_eq!(Vec::from_iter(result.iter().map(|&i| i)),
///            vec![0xB7, 0x82, 0xA1, 0xEA, 0xDE, 0xC5, 0x46, 0x3E,
///                 0x1D, 0xCF, 0x56, 0xA2, 0xD7, 0x52, 0x23, 0x82,
///                 0xA3, 0x02, 0xE6, 0xB6, 0x1D, 0x45, 0xA8, 0xBF,
///                 0x95, 0x12, 0x92, 0x1E, 0xAD, 0x21, 0x3E, 0x47]);
/// ```
impl io::Write for Md6 {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for Md6 {
    fn drop(&mut self) {
        native::free_hash_state(&mut self.raw_state);
    }
}


impl Error for Md6Error {
    fn description(&self) -> &str {
        match self {
            &Md6Error::Fail => "Generic MD6 fail",
            &Md6Error::BadHashbitlen => "Incorrect hashbitlen",
        }
    }
}

impl From<i32> for Md6Error {
    /// Passing incorrect error values yields unspecified behaviour.
    fn from(i: i32) -> Self {
        match i {
            0 => panic!("Not an error"),
            1 => Md6Error::Fail,
            2 => Md6Error::BadHashbitlen,
            _ => panic!("Incorrect error number"),
        }
    }
}

impl fmt::Display for Md6Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
