use fugue_bv::BitVec;
use fugue_core::analysis::value::StridedInterval;

fn value(value: u64, width: u32) -> BitVec {
    BitVec::from_u64(value, width)
}

#[test]
fn widening_preserves_both_phases() {
    let old = StridedInterval::range(value(12, 32), value(20, 32), value(8, 32));
    let new = StridedInterval::range(value(4, 32), value(20, 32), value(8, 32));
    let widened = old.widen(&new);

    for member in [4, 12, 20] {
        assert!(widened.contains(&value(member, 32)));
    }
}

#[test]
fn sign_extension_keeps_unsigned_lattice_ordering() {
    let negatives =
        StridedInterval::range(value(0x80, 8), value(0xff, 8), value(1, 8)).sign_extend(32);
    let joined = negatives.join(&StridedInterval::single(value(0, 32)));

    assert!(joined.contains(&value(0xffff_ff80, 32)));
    assert!(joined.contains(&value(0xffff_ffff, 32)));
    assert!(joined.contains(&value(0, 32)));
}

#[test]
fn overflowing_arithmetic_saturates_to_full() {
    let full = StridedInterval::full(8);
    let one = StridedInterval::single(value(1, 8));

    assert_eq!(&full + &one, full);
    assert_eq!(&full - &one, full);
}

#[test]
fn truncating_wrapped_bounds_saturates_to_full() {
    let interval = StridedInterval::range(value(0, 32), value(300, 32), value(1, 32));

    assert_eq!(interval.truncate(8), StridedInterval::full(8));
}

#[test]
fn mask_preserves_its_low_bit_stride() {
    let interval = StridedInterval::masked(&value(0xf0, 8));

    assert_eq!(interval.stride(), Some(&value(0x10, 8)));
    assert!(interval.contains(&value(0x80, 8)));
    assert!(!interval.contains(&value(0x88, 8)));
}
