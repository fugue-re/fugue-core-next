use std::mem::size_of;

use fugue_bv::BitVec;
use fugue_bv::error::ParseError;

#[test]
fn test_repr_size() {
    assert_eq!(size_of::<BitVec>(), 16);
}

#[test]
fn test_wrapped_add() {
    let v1 = BitVec::from(0xff00u16);
    let v2 = BitVec::from(0x0100u16);

    assert_eq!(v1 + v2, BitVec::zero(16));

    let v3 = BitVec::from_u32(0xffff00, 24);
    let v4 = BitVec::from_u32(0x000100, 24);

    assert_eq!(v3 + v4, BitVec::zero(24));

    let v5 = BitVec::from_i32(-1, 24);
    let v6 = BitVec::from_i32(1, 24);

    assert_eq!(v5 + v6, BitVec::zero(24));

    let v7 = BitVec::from_i32(-1, 100);
    let v8 = BitVec::from_i32(1, 100);

    assert_eq!(v7 + v8, BitVec::zero(100));
}

#[test]
fn test_wrapped_sub() {
    let v1 = BitVec::from(0xfffeu16);
    let v2 = BitVec::from(0xffffu16);

    assert_eq!(v1 - v2, BitVec::from(0xffffu16));

    let v3 = BitVec::from_u32(0xfffffe, 24);
    let v4 = BitVec::from_u32(0xffffff, 24);

    assert_eq!(v3 - v4, BitVec::from_u32(0xffffff, 24));

    let v5 = BitVec::from_u32(0x0, 120);
    let v6 = BitVec::from_u32(0x1, 120);

    assert_eq!(v5 - v6, -BitVec::from_i32(0x1, 120));
}

#[test]
fn test_signed_shift_right() {
    let v1 = BitVec::from(0xffffu16);
    assert_eq!(v1 >> 4u32, BitVec::from(0x0fffu16));

    let v2 = BitVec::from(0xffffu16);
    assert_eq!(v2.signed() >> 4u32, BitVec::from(0xffffu16));

    let v3 = BitVec::from(0x8000u16);
    assert_eq!(v3.signed() >> 4u32, BitVec::from(0xf800u16));

    let v4 = BitVec::from(0x05deu16);
    assert_eq!(v4.signed() >> 1u32, BitVec::from(0x2efu16));

    let v5 = BitVec::from(0x8000u16);
    assert_eq!(v5.signed() >> 16u32, BitVec::from(0xffffu16));

    let v6 = BitVec::from(0x05deu16);
    assert_eq!(v6.signed() >> 16u32, BitVec::zero(16));
}

#[test]
fn test_signed_shr_assign() {
    let mut v = BitVec::from(0x8000u16);
    v.signed_shr_assign(&BitVec::from(4u16));
    assert_eq!(v, BitVec::from(0xf800u16));
}

#[test]
fn test_signed_rem() {
    let v1 = BitVec::from(-100i64);
    let v2 = BitVec::from(-27i64);

    assert_eq!(v1.signed() % v2.signed(), BitVec::from(-19i64));

    let v3 = BitVec::from(-100i64);
    let v4 = BitVec::from(27i64);

    assert_eq!(v3.signed() % v4, BitVec::from(-19i64));

    let v5 = BitVec::from(100i64);
    let v6 = BitVec::from(-27i64);

    assert_eq!(v5 % v6.signed(), BitVec::from(19i64));

    let v7 = BitVec::from(100i64);
    let v8 = BitVec::from(27i64);

    assert_eq!(v7.signed() % v8, BitVec::from(19i64));
}

#[test]
fn test_signed_rem_euclid() {
    let v1 = BitVec::from(-100i64);
    let v2 = BitVec::from(-27i64);

    assert_eq!(v1.signed().rem_euclid(&v2.signed()), BitVec::from(8i64));

    let v3 = BitVec::from(-100i64);
    let v4 = BitVec::from(27i64);

    assert_eq!(v3.signed().rem_euclid(&v4), BitVec::from(8i64));

    let v5 = BitVec::from(100i64);
    let v6 = BitVec::from(-27i64);

    assert_eq!(v5.rem_euclid(&v6.signed()), BitVec::from(19i64));

    let v7 = BitVec::from(-7i64);
    let v8 = BitVec::from(4i64);

    assert_eq!(v7.signed().rem_euclid(&v8), BitVec::from(1i64));

    let v9 = BitVec::from_i64(-7, 13);
    let v10 = BitVec::from_i64(4, 13);

    assert_eq!(v9.signed().rem_euclid(&v10), BitVec::from_u64(1, 13));
}

#[test]
fn test_abs() {
    let v1 = BitVec::from(0x8000_0000u32).signed();
    assert_eq!(v1.abs(), BitVec::from(0x8000_0000u32));

    let v2 = BitVec::from(0x8000_0001u32).signed();
    assert_eq!(v2.abs(), BitVec::from(0x7fff_ffffu32));
}

#[test]
fn test_compare() {
    let v1 = BitVec::from(0x8000_0000u32);
    let v2 = BitVec::from(0x8000_0001u32);
    let v3 = BitVec::from(0xffff_ffffu32).signed();

    assert!(v1 < v2);
    assert!(v1 >= v3);
    assert!(v3 < v1);
    assert!(v3 < v2);
    assert_eq!(v1.clone().signed(), v1);
}

#[test]
fn test_byte_convert() {
    let v1 = BitVec::from_be_bytes(&[0xff, 0xff]);
    let v2 = BitVec::from_be_bytes(&[0x80, 0x00]);
    let v3 = BitVec::from_be_bytes(&[0x7f, 0xff]);

    assert_eq!(v1, BitVec::from(0xffffu16));
    assert_eq!(v2, BitVec::from(0x8000u16));
    assert_eq!(v3, BitVec::from(0x7fffu16));

    let mut buf = [0u8; 2];

    v2.to_be_bytes(&mut buf);
    assert_eq!(&buf, &[0x80, 0x00]);

    v2.to_le_bytes(&mut buf);
    assert_eq!(&buf, &[0x00, 0x80]);

    v3.to_le_bytes(&mut buf);
    assert_eq!(&buf, &[0xff, 0x7f]);

    let v4 = "0xffffffffffffffffffffffffffffffff:128"
        .parse::<BitVec>()
        .unwrap();
    let v5 = "0x7fffffffffffffffffffffffffffffff:128"
        .parse::<BitVec>()
        .unwrap();

    let mut buf = [0u8; 16];

    v4.to_be_bytes(&mut buf);
    assert_eq!(buf, [0xff; 16]);
    assert_eq!(BitVec::from_be_bytes(&buf), v4);

    v5.to_le_bytes(&mut buf);
    assert_eq!(buf[15], 0x7f);
    assert_eq!(BitVec::from_le_bytes(&buf), v5);
}

#[test]
fn test_byte_convert_with() {
    let v1 = BitVec::from_be_bytes_with(&[0xff, 0xff], 12);
    assert_eq!(v1, BitVec::from_u64(0xfff, 12));
    assert_eq!(v1.bits(), 12);
    assert_eq!(v1.bytes(), 2);

    let mut buf = [0u8; 2];
    v1.to_be_bytes(&mut buf);
    assert_eq!(&buf, &[0x0f, 0xff]);

    let v2 = BitVec::from_le_bytes_with(&[0xff, 0xff], 12);
    assert_eq!(v2, BitVec::from_u64(0xfff, 12));

    v2.to_le_bytes(&mut buf);
    assert_eq!(&buf, &[0xff, 0x0f]);

    let v3 = BitVec::from_be_bytes_with(&[0xff; 13], 100);
    assert_eq!(v3, BitVec::max_value_with(100, false));

    let v4 = BitVec::from_u128((1u128 << 99) | 0xabcd, 100);
    let mut buf = [0u8; 13];

    v4.to_be_bytes(&mut buf);
    assert_eq!(BitVec::from_be_bytes_with(&buf, 100), v4);

    v4.to_le_bytes(&mut buf);
    assert_eq!(BitVec::from_le_bytes_with(&buf, 100), v4);
}

#[test]
fn test_to_int_sign_extension() {
    assert_eq!(BitVec::from_i32(-1, 24).to_i32(), Some(-1));
    assert_eq!(BitVec::from_u64(0xfff, 12).to_i16(), Some(-1));
    assert_eq!(BitVec::from_u64(0xfff, 12).to_u16(), Some(0xfff));
    assert_eq!(BitVec::from_u64(200, 16).to_i8(), None);
    assert_eq!(BitVec::from_u64(200, 16).to_i16(), Some(200));
    assert_eq!(BitVec::from_i32(-1, 100).to_i64(), Some(-1));
    assert_eq!(BitVec::from_u128(1 << 80, 100).to_i128(), Some(1 << 80));
    assert_eq!(BitVec::from_u128(1 << 80, 100).to_u64(), None);
}

#[test]
fn test_signed_borrow() {
    let v1 = BitVec::from(0x8000u16);
    let v2 = BitVec::from(0x1u16);

    assert!(v1.signed_borrow(&v2));

    let v3 = BitVec::from(0x8001u16);
    let v4 = BitVec::from(0x1u16);

    assert!(!v3.signed_borrow(&v4));
}

#[test]
fn test_gcd() {
    let a = BitVec::from(12u16);
    let b = BitVec::from(-18i16);

    let (g, x, y) = a.gcd_ext(&b);

    assert_eq!(g, BitVec::from(6u16));
    assert_eq!(g, &a * &x + &b * &y);

    let c = BitVec::from_u64(12, 100);
    let d = BitVec::from_i64(-18, 100);

    assert_eq!(c.gcd(&d), BitVec::from_u64(6, 100));

    let (g, x, y) = c.gcd_ext(&d);

    assert_eq!(g, BitVec::from_u64(6, 100));
    assert_eq!(g, &c * &x + &d * &y);

    assert_eq!(
        BitVec::from(4u16).lcm(&BitVec::from(6u16)),
        BitVec::from(12u16)
    );
}

#[test]
fn test_leading() {
    let v1 = BitVec::from(0xffu16);

    assert_eq!(v1.leading_ones(), 0);
    assert_eq!(v1.leading_one(), Some(7));
    assert_eq!(v1.leading_zeros(), 8);

    let v2 = BitVec::from_u64(0xff, 12);

    assert_eq!(v2.leading_zeros(), 4);
    assert_eq!(v2.leading_one(), Some(7));
    assert_eq!(v2.leading_ones(), 0);

    let v3 = BitVec::from_u64(0xf00, 12);

    assert_eq!(v3.leading_ones(), 4);

    let v4 = BitVec::from_u64(0xff, 100);

    assert_eq!(v4.leading_zeros(), 92);
    assert_eq!((!BitVec::zero(100)).leading_ones(), 100);
}

#[test]
fn test_count() {
    let v1 = BitVec::from_u32(0xff, 16);

    assert_eq!(v1.count_ones(), 8);
    assert_eq!(v1.count_zeros(), 8);

    let v2 = BitVec::from_u64(0xff, 12);

    assert_eq!(v2.count_ones(), 8);
    assert_eq!(v2.count_zeros(), 4);

    assert_eq!(BitVec::max_value_with(100, false).count_ones(), 100);
}

#[test]
fn test_min_max_value() {
    assert_eq!(BitVec::max_value_with(3, false), BitVec::from_u64(7, 3));
    assert_eq!(BitVec::max_value_with(3, true), BitVec::from_u64(3, 3));
    assert_eq!(BitVec::min_value_with(3, true).to_i8(), Some(-4));
    assert_eq!(BitVec::min_value_with(3, false), BitVec::zero(3));
    assert_eq!(BitVec::min_value_with(100, true), BitVec::one(100) << 99u32);
    assert_eq!(BitVec::max_value_with(100, false), !BitVec::zero(100));
}

#[test]
fn test_cast() {
    assert_eq!(BitVec::from_i32(-3, 12).signed_cast(100).to_i32(), Some(-3));
    assert_eq!(BitVec::from_i64(-3, 100).signed_cast(12).to_i32(), Some(-3));
    assert_eq!(BitVec::from_i32(-1, 8).signed_cast(72).to_i64(), Some(-1));

    let v1 = BitVec::from_u64(u64::MAX, 64).unsigned_cast(65) + BitVec::one(65);
    assert_eq!(v1.to_u128(), Some(1u128 << 64));

    let v2 = BitVec::from_u128((0xabu128 << 64) | 0x1234, 96);
    assert_eq!(v2.unsigned_cast(16), BitVec::from_u64(0x1234, 16));

    let mut v3 = BitVec::from_u64(0x8fff, 16);
    v3.signed_cast_assign(100);
    assert_eq!(v3.to_i64(), Some(-28673));
}

#[test]
fn test_1bit() {
    let v0 = BitVec::zero(1);
    assert_eq!(v0.bits(), 1);

    let v1 = v0.max_value();
    assert_eq!(v1, BitVec::from_u64(0b1, 1));

    let v2 = BitVec::one(1);
    assert_eq!(v2, BitVec::from_u64(0b1, 1));

    assert_eq!(v1 - v2.clone(), BitVec::from_u64(0b0, 1));
    assert_eq!(v0 - v2, BitVec::from_u64(0b1, 1));
}

#[test]
fn test_3bit() {
    let v0 = BitVec::zero(3);
    assert_eq!(v0.bits(), 3);

    let v1 = v0.max_value();
    assert_eq!(v1, BitVec::from_u64(0b111, 3));

    let v2 = BitVec::one(3);
    assert_eq!(v2, BitVec::from_u64(0b1, 3));

    assert_eq!(v1.clone() - v2.clone(), BitVec::from_u64(0b110, 3));
    assert_eq!(v0 - v2, BitVec::from_u64(0b111, 3));

    assert_eq!(
        BitVec::from_u64(5, 3) * (-BitVec::from_u64(3, 3)),
        BitVec::from_u64(1, 3)
    );
}

#[test]
fn test_set_bit() {
    let mut v1 = BitVec::zero(3);
    v1.set_bit(1);
    assert_eq!(v1, BitVec::from_u64(2, 3));
    v1.set_bit(5);
    assert_eq!(v1, BitVec::from_u64(2, 3));

    let mut v2 = BitVec::zero(100);
    v2.set_bit(99);
    assert_eq!(v2, BitVec::one(100) << 99u32);
    assert!(v2.msb());
    assert!(!v2.lsb());
}

#[test]
fn test_display() {
    assert_eq!(format!("{}", BitVec::from_u64(255, 12)), "255:12");
    assert_eq!(format!("{:#x}", BitVec::from_u64(255, 12)), "0xff:12");
    assert_eq!(
        format!("{:#x}", BitVec::from_u128(1u128 << 64, 65)),
        "0x10000000000000000:65"
    );
}

#[test]
fn test_parse() {
    assert_eq!("0x100:129".parse::<BitVec>().unwrap().bits(), 129);
    assert_eq!(
        "0x100:12".parse::<BitVec>().unwrap(),
        BitVec::from_u64(0x100, 12)
    );
    assert!(matches!(
        "0x100:0".parse::<BitVec>(),
        Err(ParseError::InvalidSize)
    ));
    assert!(matches!(
        "123".parse::<BitVec>(),
        Err(ParseError::InvalidFormat)
    ));
    assert!(matches!(
        "0xzz:8".parse::<BitVec>(),
        Err(ParseError::InvalidConst)
    ));
    assert_eq!(
        BitVec::from_str_radix("ff:8", 16).unwrap(),
        BitVec::from(0xffu8)
    );
}

#[test]
fn test_sub_byte_wrapping() {
    assert_eq!(BitVec::from_u64(7, 3) + BitVec::one(3), BitVec::zero(3));
    assert_eq!(
        BitVec::from_u64(5, 3) + BitVec::from_u64(6, 3),
        BitVec::from_u64(3, 3)
    );
    assert_eq!(
        BitVec::one(3) - BitVec::from_u64(3, 3),
        BitVec::from_u64(6, 3)
    );
    assert_eq!(
        BitVec::from_u64(5, 3) * BitVec::from_u64(3, 3),
        BitVec::from_u64(7, 3)
    );

    assert_eq!(-BitVec::from_u64(4, 3), BitVec::from_u64(4, 3));
    assert_eq!(-BitVec::one(3), BitVec::from_u64(7, 3));
    assert_eq!(-BitVec::zero(3), BitVec::zero(3));

    assert_eq!(BitVec::max_value_with(3, false).succ(), BitVec::zero(3));
    assert_eq!(BitVec::zero(3).pred(), BitVec::from_u64(7, 3));

    assert_eq!(BitVec::one(1) + BitVec::one(1), BitVec::zero(1));
    assert_eq!(BitVec::from_u64(1, 1).to_i8(), Some(-1));
}

#[test]
fn test_sub_byte_division() {
    let min = BitVec::from_u64(4, 3);
    let neg_one = BitVec::from_u64(7, 3);

    assert_eq!(min.signed_div(&neg_one), min);
    assert_eq!(min.signed_div(&BitVec::one(3)), min);
    assert_eq!(neg_one.signed_div(&BitVec::from_u64(2, 3)), BitVec::zero(3));
    assert_eq!(
        BitVec::from_u64(7, 3) / BitVec::from_u64(2, 3),
        BitVec::from_u64(3, 3)
    );

    assert_eq!(
        BitVec::from_u64(5, 3).signed_rem(&BitVec::from_u64(2, 3)),
        BitVec::from_u64(7, 3)
    );
    assert_eq!(
        BitVec::from_u64(5, 3)
            .signed()
            .rem_euclid(&BitVec::from_u64(2, 3)),
        BitVec::one(3)
    );
}

#[test]
fn test_sub_byte_carry_borrow_shift() {
    assert!(BitVec::from_u64(7, 3).carry(&BitVec::one(3)));
    assert!(!BitVec::from_u64(6, 3).carry(&BitVec::one(3)));
    assert!(BitVec::from_u64(3, 3).signed_carry(&BitVec::one(3)));
    assert!(!BitVec::from_u64(2, 3).signed_carry(&BitVec::one(3)));
    assert!(BitVec::from_u64(4, 3).signed_borrow(&BitVec::one(3)));
    assert!(!BitVec::from_u64(4, 3).signed_borrow(&BitVec::from_u64(7, 3)));
    assert!(BitVec::one(1).carry(&BitVec::one(1)));

    assert_eq!(
        BitVec::from_u64(4, 3).signed() >> 1u32,
        BitVec::from_u64(6, 3)
    );
    assert_eq!(
        BitVec::from_u64(4, 3).signed() >> 5u32,
        BitVec::from_u64(7, 3)
    );
    assert_eq!(BitVec::from_u64(3, 3).signed() >> 5u32, BitVec::zero(3));
    assert_eq!(BitVec::from_u64(3, 3) >> 1u32, BitVec::one(3));
    assert_eq!(BitVec::one(3) << 2u32, BitVec::from_u64(4, 3));
    assert_eq!(BitVec::one(3) << 3u32, BitVec::zero(3));
    assert_eq!(
        BitVec::from_u64(4, 3) >> BitVec::one(3),
        BitVec::from_u64(2, 3)
    );
}

#[test]
fn test_sub_byte_bytes_and_casts() {
    let v1 = BitVec::from_be_bytes_with(&[0xff], 3);
    assert_eq!(v1, BitVec::from_u64(7, 3));
    assert_eq!(v1.bits(), 3);
    assert_eq!(v1.bytes(), 1);

    let mut buf = [0u8; 1];
    v1.to_be_bytes(&mut buf);
    assert_eq!(&buf, &[0x07]);

    assert_eq!(
        BitVec::from_le_bytes_with(&[0b101], 3),
        BitVec::from_u64(5, 3)
    );

    assert_eq!(BitVec::from_u64(6, 3).signed_cast(8).to_i8(), Some(-2));
    assert_eq!(
        BitVec::from_u64(6, 3).unsigned_cast(8),
        BitVec::from_u64(6, 8)
    );
    assert_eq!(
        BitVec::from_u64(0xff, 8).unsigned_cast(3),
        BitVec::from_u64(7, 3)
    );
    assert_eq!(
        BitVec::from_u64(6, 3).signed_cast(100).signed_cast(3),
        BitVec::from_u64(6, 3)
    );

    assert_eq!(BitVec::from_u64(7, 3).to_i8(), Some(-1));
    assert_eq!(BitVec::from_u64(7, 3).to_u8(), Some(7));
    assert_eq!(BitVec::from_u64(3, 3).to_i8(), Some(3));

    assert!(BitVec::from_u64(7, 3).signed() < BitVec::one(3).signed());
}

#[test]
fn test_7bit() {
    assert_eq!(BitVec::from_u64(127, 7) + BitVec::one(7), BitVec::zero(7));
    assert_eq!(
        BitVec::from_u64(100, 7) + BitVec::from_u64(50, 7),
        BitVec::from_u64(22, 7)
    );
    assert_eq!(
        BitVec::from_u64(3, 7) - BitVec::from_u64(5, 7),
        BitVec::from_u64(126, 7)
    );
    assert_eq!(
        BitVec::from_u64(20, 7) * BitVec::from_u64(13, 7),
        BitVec::from_u64(4, 7)
    );

    let min = BitVec::from_i64(-64, 7);
    assert_eq!(min, BitVec::from_u64(0x40, 7));
    assert_eq!(-&min, min);
    assert_eq!(min.signed_div(&BitVec::from_i64(-1, 7)), min);
    assert_eq!(min.to_i8(), Some(-64));

    assert_eq!(
        BitVec::from_i64(-50, 7).signed_div(&BitVec::from_u64(7, 7)),
        BitVec::from_i64(-7, 7)
    );
    assert_eq!(
        BitVec::from_i64(-50, 7).signed_rem(&BitVec::from_u64(7, 7)),
        BitVec::from_i64(-1, 7)
    );
    assert_eq!(
        BitVec::from_i64(-50, 7)
            .signed()
            .rem_euclid(&BitVec::from_u64(7, 7)),
        BitVec::from_u64(6, 7)
    );

    assert!(BitVec::from_u64(127, 7).carry(&BitVec::one(7)));
    assert!(!BitVec::from_u64(126, 7).carry(&BitVec::one(7)));
    assert!(BitVec::from_u64(63, 7).signed_carry(&BitVec::one(7)));
    assert!(!BitVec::from_u64(62, 7).signed_carry(&BitVec::one(7)));
    assert!(min.signed_borrow(&BitVec::one(7)));
    assert!(!min.signed_borrow(&BitVec::from_i64(-1, 7)));

    assert_eq!(min.clone().signed() >> 3u32, BitVec::from_i64(-8, 7));
    assert_eq!(min.clone().signed() >> 10u32, BitVec::from_i64(-1, 7));
    assert_eq!(BitVec::from_u64(63, 7).signed() >> 10u32, BitVec::zero(7));
    assert_eq!(BitVec::one(7) << 6u32, min);
    assert_eq!(BitVec::one(7) << 7u32, BitVec::zero(7));

    let v1 = BitVec::from_be_bytes_with(&[0xff], 7);
    assert_eq!(v1, BitVec::from_u64(127, 7));

    let mut buf = [0u8; 1];
    v1.to_be_bytes(&mut buf);
    assert_eq!(&buf, &[0x7f]);

    let v2 = BitVec::from_le_bytes_with(&[0x55], 7);
    assert_eq!(v2, BitVec::from_u64(0x55, 7));

    v2.to_le_bytes(&mut buf);
    assert_eq!(&buf, &[0x55]);

    assert_eq!(min.signed_cast(8), BitVec::from_u64(0xc0, 8));
    assert_eq!(min.signed_cast(8).to_i8(), Some(-64));
    assert_eq!(
        BitVec::from_u64(0xff, 8).unsigned_cast(7),
        BitVec::from_u64(127, 7)
    );
    assert_eq!(
        BitVec::from_i64(-2, 7).signed_cast(100).signed_cast(7),
        BitVec::from_i64(-2, 7)
    );

    assert_eq!(BitVec::from_u64(127, 7).to_i8(), Some(-1));
    assert_eq!(BitVec::from_u64(127, 7).to_u8(), Some(127));
    assert_eq!(BitVec::from_u64(63, 7).to_i8(), Some(63));
}

#[test]
fn test_serde_roundtrip() {
    let v1 = BitVec::from_u64(0xfff, 12).signed();
    let v2 = BitVec::from_u128(1 << 80, 100);

    let s1 = serde_json::to_string(&v1).unwrap();
    let s2 = serde_json::to_string(&v2).unwrap();

    let r1 = serde_json::from_str::<BitVec>(&s1).unwrap();
    let r2 = serde_json::from_str::<BitVec>(&s2).unwrap();

    assert_eq!(r1, v1);
    assert!(r1.is_signed());
    assert_eq!(r2, v2);
}
