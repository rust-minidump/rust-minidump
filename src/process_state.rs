use std::io::prelude::*;
use std::io::Result;

pub struct ProcessState;

impl ProcessState {
    pub fn print<T : Write>(&self, _f : &mut T) -> Result<()> {
        Ok(())
    }
}
