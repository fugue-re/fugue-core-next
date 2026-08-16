use fugue_bv::BitVec;

use super::ECodeOpcode;

#[test]
fn evaluate_folds_comparisons_at_operand_width() {
    let seven = BitVec::from_u64(7, 32);
    let nine = BitVec::from_u64(9, 32);
    let one = BitVec::from_u64(1, 1);
    let zero = BitVec::from_u64(0, 1);

    assert_eq!(
        ECodeOpcode::IntLess.evaluate(1, &[seven.clone(), nine.clone()]),
        Some(one.clone())
    );
    assert_eq!(
        ECodeOpcode::IntLessEqual.evaluate(1, &[seven.clone(), seven.clone()]),
        Some(one.clone())
    );
    assert_eq!(
        ECodeOpcode::IntEqual.evaluate(1, &[seven.clone(), nine.clone()]),
        Some(zero.clone())
    );
    assert_eq!(
        ECodeOpcode::IntNotEqual.evaluate(1, &[seven.clone(), nine.clone()]),
        Some(one.clone())
    );

    let minus_one = BitVec::from_u64(u64::from(u32::MAX), 32);
    assert_eq!(
        ECodeOpcode::IntSignedLess.evaluate(1, &[minus_one.clone(), seven.clone()]),
        Some(one.clone())
    );
    assert_eq!(
        ECodeOpcode::IntLess.evaluate(1, &[minus_one, seven.clone()]),
        Some(zero)
    );
}

#[test]
fn evaluate_folds_unsigned_comparisons_of_sign_extended_operands() {
    let extended = ECodeOpcode::SignExtend
        .evaluate(16, &[BitVec::from_u64(0x80, 8)])
        .expect("sign extension folds");
    assert_eq!(extended, BitVec::from_u64(0xff80, 16).signed());

    let five = BitVec::from_u64(5, 16);
    let zero = BitVec::from_u64(0, 1);
    assert_eq!(
        ECodeOpcode::IntLess.evaluate(1, &[extended.clone(), five.clone()]),
        Some(zero.clone())
    );
    assert_eq!(
        ECodeOpcode::IntLessEqual.evaluate(1, &[extended.clone(), five]),
        Some(zero)
    );
    assert_eq!(
        ECodeOpcode::IntSignedLess.evaluate(1, &[extended, BitVec::from_u64(5, 16)]),
        Some(BitVec::from_u64(1, 1))
    );
}

#[test]
fn evaluate_folds_byte_wide_boolean_operations_to_zero_or_one() {
    let zero = BitVec::from_u64(0, 8);
    let one = BitVec::from_u64(1, 8);
    let nonzero = BitVec::from_u64(0x80, 8);

    assert_eq!(
        ECodeOpcode::BoolAnd.evaluate(8, &[one.clone(), nonzero.clone()]),
        Some(one.clone())
    );
    assert_eq!(
        ECodeOpcode::BoolOr.evaluate(8, &[zero.clone(), nonzero.clone()]),
        Some(one.clone())
    );
    assert_eq!(
        ECodeOpcode::BoolXor.evaluate(8, &[one.clone(), nonzero.clone()]),
        Some(zero.clone())
    );
    assert_eq!(
        ECodeOpcode::BoolNot.evaluate(8, std::slice::from_ref(&one)),
        Some(zero.clone())
    );
    assert_eq!(
        ECodeOpcode::BoolNot.evaluate(8, std::slice::from_ref(&zero)),
        Some(one)
    );
}

#[test]
fn evaluate_guards_width_mismatch_and_zero_divisor() {
    let wide = BitVec::from_u64(7, 32);
    let narrow = BitVec::from_u64(7, 16);
    assert_eq!(
        ECodeOpcode::IntLess.evaluate(1, &[wide.clone(), narrow]),
        None
    );

    let zero = BitVec::from_u64(0, 32);
    assert_eq!(
        ECodeOpcode::UnsignedDiv.evaluate(32, &[wide.clone(), zero.clone()]),
        None
    );
    assert_eq!(ECodeOpcode::SignedRem.evaluate(32, &[wide, zero]), None);
}

#[test]
fn evaluate_folds_division_and_bit_counts() {
    assert_eq!(
        ECodeOpcode::UnsignedDiv.evaluate(32, &[BitVec::from_u64(20, 32), BitVec::from_u64(6, 32)]),
        Some(BitVec::from_u64(3, 32))
    );
    assert_eq!(
        ECodeOpcode::UnsignedRem.evaluate(32, &[BitVec::from_u64(20, 32), BitVec::from_u64(6, 32)]),
        Some(BitVec::from_u64(2, 32))
    );
    assert_eq!(
        ECodeOpcode::CountOnes.evaluate(32, &[BitVec::from_u64(0b1011, 32)]),
        Some(BitVec::from_u64(3, 32))
    );
    assert_eq!(
        ECodeOpcode::CountLeadingZeros.evaluate(32, &[BitVec::from_u64(1, 32)]),
        Some(BitVec::from_u64(31, 32))
    );
}

#[test]
fn evaluate_folds_carries_and_borrows() {
    let one = BitVec::from_u64(1, 1);
    let zero = BitVec::from_u64(0, 1);
    let max = BitVec::from_u64(u64::from(u32::MAX), 32);
    let signed_min = BitVec::from_u64(0x8000_0000, 32);
    let signed_max = BitVec::from_u64(0x7fff_ffff, 32);
    let unit = BitVec::from_u64(1, 32);

    assert_eq!(
        ECodeOpcode::Carry.evaluate(1, &[max.clone(), unit.clone()]),
        Some(one.clone())
    );
    assert_eq!(
        ECodeOpcode::Carry.evaluate(1, &[unit.clone(), unit.clone()]),
        Some(zero.clone())
    );
    assert_eq!(
        ECodeOpcode::Carry.evaluate(1, &[max.signed(), unit.clone()]),
        Some(one.clone())
    );

    assert_eq!(
        ECodeOpcode::SignedCarry.evaluate(1, &[signed_max, unit.clone()]),
        Some(one.clone())
    );
    assert_eq!(
        ECodeOpcode::SignedCarry.evaluate(1, &[unit.clone(), unit.clone()]),
        Some(zero.clone())
    );
    assert_eq!(
        ECodeOpcode::SignedBorrow.evaluate(1, &[signed_min, unit.clone()]),
        Some(one)
    );
    assert_eq!(
        ECodeOpcode::SignedBorrow.evaluate(1, &[BitVec::from_u64(0, 32), unit]),
        Some(zero)
    );
}

#[test]
fn evaluate_folds_boolean_and_signed_operations() {
    let one = BitVec::from_u64(1, 1);
    let zero = BitVec::from_u64(0, 1);

    assert_eq!(
        ECodeOpcode::BoolAnd.evaluate(1, &[one.clone(), zero.clone()]),
        Some(zero.clone())
    );
    assert_eq!(
        ECodeOpcode::BoolOr.evaluate(1, &[one.clone(), zero.clone()]),
        Some(one.clone())
    );
    assert_eq!(
        ECodeOpcode::BoolXor.evaluate(1, &[one.clone(), one.clone()]),
        Some(zero.clone())
    );
    assert_eq!(
        ECodeOpcode::BoolNot.evaluate(1, std::slice::from_ref(&zero)),
        Some(one.clone())
    );

    let minus_twenty = BitVec::from_u64((-20i64) as u64, 32);
    let six = BitVec::from_u64(6, 32);
    assert_eq!(
        ECodeOpcode::SignedDiv
            .evaluate(32, &[minus_twenty.clone(), six.clone()])
            .map(BitVec::unsigned),
        Some(BitVec::from_u64((-3i64) as u64, 32))
    );
    assert_eq!(
        ECodeOpcode::SignedRem
            .evaluate(32, &[minus_twenty.clone(), six.clone()])
            .map(BitVec::unsigned),
        Some(BitVec::from_u64((-2i64) as u64, 32))
    );
    assert_eq!(
        ECodeOpcode::IntSignedLessEqual.evaluate(1, &[minus_twenty, six]),
        Some(one)
    );
}

#[test]
fn evaluate_leaves_extract_and_insert_unfolded() {
    let operand = BitVec::from_u64(0xff, 32);
    assert_eq!(
        ECodeOpcode::Extract.evaluate(8, std::slice::from_ref(&operand)),
        None
    );
    assert_eq!(
        ECodeOpcode::Insert.evaluate(32, &[operand.clone(), operand]),
        None
    );
}
