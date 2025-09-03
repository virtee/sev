// SPDX-License-Identifier: Apache-2.0

use std::fmt::{self, Display, Formatter};

pub(crate) struct HexLine<'a>(pub &'a [u8]);

impl Display for HexLine<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(f)?; // leading newline
        for (i, byte) in self.0.iter().enumerate() {
            if i > 0 && i % 16 == 0 {
                writeln!(f)?;
            } else if i > 0 {
                write!(f, " ")?;
            }
            write!(f, "{byte:02X}")?;
        }
        Ok(())
    }
}
