use fugue_lifter_runtime::{Language, Lifter};

mod __impl {
    #![allow(unused)]
    include!(concat!(env!("OUT_DIR"), "/x86_64.rs"));
}

pub use __impl::{context, register, space, user_op, LANGUAGE_COMPAT32, LANGUAGE_DEFAULT};

pub struct LifterFactory;

impl LifterFactory {
    pub fn new_default() -> Lifter {
        Lifter::new(&__impl::LANGUAGE_DEFAULT)
    }

    pub fn new_compat32() -> Lifter {
        Lifter::new(&__impl::LANGUAGE_COMPAT32)
    }
}

pub mod variants {
    use super::*;

    pub const DEFAULT: &Language = &__impl::LANGUAGE_DEFAULT;
    pub const COMPAT32: &Language = &__impl::LANGUAGE_COMPAT32;
}

#[cfg(test)]
mod test {
    use fugue_lifter_runtime::{OperandKind, OperandPiece, Operands};

    use super::*;

    #[test]
    fn variant_tag_matches_factory() {
        assert_eq!(LifterFactory::new_default().language().variant(), "default");
        assert_eq!(
            LifterFactory::new_compat32().language().variant(),
            "compat32"
        );
    }

    fn decode(bytes: &[u8]) -> Operands {
        let mut disassembler = LifterFactory::new_default();
        let mut disassembly = String::new();
        disassembler
            .disassemble(0x1000, bytes, &mut disassembly)
            .expect("disassembled");

        let mut lifter = LifterFactory::new_default();
        let mut operands = Operands::new();
        lifter
            .operands(0x1000, bytes, &mut operands)
            .expect("operands");

        assert_eq!(
            operands.to_string(),
            disassembly,
            "reconstruction mismatch for {bytes:02x?}"
        );

        operands
    }

    #[test]
    fn absolute_memory_operands_match_by_address() {
        let loaded = decode(&[0x48, 0x8b, 0x04, 0x25, 0x34, 0x12, 0x00, 0x00]);
        let load = loaded.operand(1).unwrap();
        assert_eq!(load.kind(), OperandKind::DataAddress);
        assert!(load.is_read());
        assert!(!load.is_write());
        assert!(!load.is_indirect());

        let stored = decode(&[0x48, 0x89, 0x04, 0x25, 0x34, 0x12, 0x00, 0x00]);
        let destination = stored.operand(0).unwrap();
        assert_eq!(destination.kind(), OperandKind::DataAddress);
        assert!(destination.is_write());
        assert!(!destination.is_read());
        let source = stored.operand(1).unwrap();
        assert!(source.is_read());
        assert!(!source.is_write());

        let called = decode(&[0xff, 0x14, 0x25, 0x34, 0x12, 0x00, 0x00]);
        let target = called.operand(0).unwrap();
        assert_eq!(target.kind(), OperandKind::DataAddress);
        assert!(target.is_read());
        assert!(!target.is_write());
        assert!(target.is_indirect());
    }

    #[test]
    fn reconstruction_matches_disassembly() {
        let cases: &[&[u8]] = &[
            &[0x48, 0x89, 0xd8],
            &[0x89, 0xc8],
            &[0x48, 0x8b, 0x03],
            &[0x48, 0x8b, 0x43, 0x10],
            &[0x48, 0x89, 0x03],
            &[0x48, 0x01, 0x03],
            &[0x48, 0x83, 0xc0, 0x10],
            &[0xe8, 0x00, 0x00, 0x00, 0x00],
            &[0xe9, 0x00, 0x00, 0x00, 0x00],
            &[0xff, 0xd0],
            &[0xff, 0x13],
            &[0xc3],
            &[0x90],
            &[0x48, 0x01, 0xd8],
            &[0x48, 0x8b, 0x04, 0x25, 0x34, 0x12, 0x00, 0x00],
            &[0x48, 0x89, 0x04, 0x25, 0x34, 0x12, 0x00, 0x00],
            &[0xff, 0x14, 0x25, 0x34, 0x12, 0x00, 0x00],
        ];

        for bytes in cases {
            decode(bytes);
        }
    }

    #[test]
    fn reused_context_matches_fresh_decodes() {
        let cases: &[&[u8]] = &[
            &[0xe8, 0x00, 0x00, 0x00, 0x00],
            &[0x48, 0x8b, 0x43, 0x10],
            &[0x48, 0x89, 0xd8],
            &[0xff, 0x14, 0x25, 0x34, 0x12, 0x00, 0x00],
            &[0x90],
        ];

        let mut lifter = LifterFactory::new_default();
        let mut operands = Operands::new();

        for bytes in cases {
            lifter
                .operands(0x1000, bytes, &mut operands)
                .expect("operands");

            let fresh = decode(bytes);

            assert_eq!(operands.to_string(), fresh.to_string());
            assert_eq!(operands.len(), fresh.len());
            for (reused, expected) in operands.iter().zip(fresh.iter()) {
                assert_eq!(reused.kind(), expected.kind());
                assert_eq!(reused.access(), expected.access());
                assert_eq!(reused.pieces(), expected.pieces());
            }
        }
    }

    #[test]
    fn register_move_reads_source_writes_destination() {
        let operands = decode(&[0x48, 0x89, 0xd8]);

        assert_eq!(operands.mnemonic(), "MOV");
        assert_eq!(operands.len(), 2);

        let destination = operands.operand(0).unwrap();
        assert_eq!(destination.kind(), OperandKind::Register);
        assert_eq!(
            destination.register().map(|register| register.name()),
            Some("RAX")
        );
        assert_eq!(
            destination.register().map(|register| register.size()),
            Some(8)
        );
        assert!(destination.is_write());
        assert!(!destination.is_read());

        let source = operands.operand(1).unwrap();
        assert_eq!(
            source.register().map(|register| register.name()),
            Some("RBX")
        );
        assert!(source.is_read());
        assert!(!source.is_write());
    }

    #[test]
    fn sub_register_destination_ignores_zero_extension_read() {
        let operands = decode(&[0x89, 0xc8]);

        let destination = operands.operand(0).unwrap();
        assert_eq!(
            destination.register().map(|register| register.size()),
            Some(4)
        );
        assert!(destination.is_write());
        assert!(!destination.is_read());
    }

    #[test]
    fn immediate_operand_is_a_read_scalar() {
        let operands = decode(&[0x48, 0x83, 0xc0, 0x10]);

        let immediate = operands.operand(1).unwrap();
        assert_eq!(immediate.kind(), OperandKind::Scalar);
        assert_eq!(immediate.scalar().map(|scalar| scalar.value()), Some(0x10));
        assert!(immediate.is_read());

        let accumulator = operands.operand(0).unwrap();
        assert!(accumulator.is_read());
        assert!(accumulator.is_write());
    }

    #[test]
    fn memory_load_reads_and_store_writes() {
        let loaded = decode(&[0x48, 0x8b, 0x43, 0x10]);
        let load = loaded.operand(1).unwrap();
        assert_eq!(load.kind(), OperandKind::Dynamic);
        assert!(load.is_read());
        assert!(!load.is_write());
        assert!(load.pieces().iter().any(
            |piece| matches!(piece, OperandPiece::Register(register) if register.name() == "RBX")
        ));

        let stored = decode(&[0x48, 0x89, 0x03]);
        let store = stored.operand(0).unwrap();
        assert_eq!(store.kind(), OperandKind::Dynamic);
        assert!(store.is_write());
        assert!(!store.is_read());

        let added = decode(&[0x48, 0x01, 0x03]);
        let read_modify_write = added.operand(0).unwrap();
        assert!(read_modify_write.is_read());
        assert!(read_modify_write.is_write());
    }

    #[test]
    fn direct_call_and_jump_targets_are_code_addresses() {
        for bytes in [
            [0xe8, 0x00, 0x00, 0x00, 0x00],
            [0xe9, 0x00, 0x00, 0x00, 0x00],
        ] {
            let operands = decode(&bytes);
            let target = operands.operand(0).unwrap();
            assert_eq!(target.kind(), OperandKind::CodeAddress);
            assert_eq!(target.address(), Some(0x1005));
        }
    }

    #[test]
    fn indirect_call_targets_are_marked_indirect() {
        let direct = decode(&[0xff, 0xd0]);
        let register = direct.operand(0).unwrap();
        assert_eq!(register.kind(), OperandKind::Register);
        assert!(register.is_indirect());
        assert!(register.is_read());

        let loaded = decode(&[0xff, 0x13]);
        let memory = loaded.operand(0).unwrap();
        assert_eq!(memory.kind(), OperandKind::Dynamic);
        assert!(memory.is_indirect());
        assert!(memory.is_read());
    }

    #[test]
    fn operandless_instructions_have_no_operands() {
        assert!(decode(&[0xc3]).is_empty());
        assert!(decode(&[0x90]).is_empty());
    }
}
