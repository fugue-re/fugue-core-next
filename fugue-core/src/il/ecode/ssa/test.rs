use std::mem::size_of;

use super::{ECodeSsaBlockArg, ECodeSsaOp, ECodeSsaValue};

#[test]
fn ssa_records_stay_compact() {
    assert!(size_of::<ECodeSsaValue>() <= 12);
    assert!(size_of::<ECodeSsaBlockArg>() <= 12);
    assert!(size_of::<ECodeSsaOp>() <= 64);
}
