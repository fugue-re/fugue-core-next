use bincode::{Decode, Encode};

use crate::ir::Address;

#[derive(Debug, Copy, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Decode, Encode)]
pub struct StackChangePoint {
    /// The stack pointer change point.
    address: Address,
    /// The stack pointer change value.
    delta: i64,
}

impl StackChangePoint {
    pub fn new(address: impl Into<Address>, delta: i64) -> Self {
        StackChangePoint {
            address: address.into(),
            delta,
        }
    }

    pub fn address(&self) -> Address {
        self.address
    }

    pub fn delta(&self) -> i64 {
        self.delta
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Decode, Encode)]
pub struct FunctionFrame {
    /// The size of local (stack) variables in bytes.
    locals_size: usize,
    /// The size of the preserved registers in bytes.
    preserved_registers_size: usize,
    /// The function's frame (stack) pointer delta.
    frame_pointer_delta: i64,
    /// The function's stack pointer change points.
    change_points: Vec<StackChangePoint>,
}

impl FunctionFrame {
    pub fn new(
        locals_size: usize,
        preserved_registers_size: usize,
        frame_pointer_delta: i64,
    ) -> Self {
        FunctionFrame {
            locals_size,
            preserved_registers_size,
            frame_pointer_delta,
            change_points: Vec::new(),
        }
    }

    pub fn add_change_point(&mut self, address: impl Into<Address>, delta: i64) {
        self.change_points
            .push(StackChangePoint::new(address, delta));
    }

    pub fn locals_size(&self) -> usize {
        self.locals_size
    }

    pub fn preserved_registers_size(&self) -> usize {
        self.preserved_registers_size
    }

    pub fn frame_pointer_delta(&self) -> i64 {
        self.frame_pointer_delta
    }

    pub fn change_points(&self) -> &[StackChangePoint] {
        &self.change_points
    }
}
