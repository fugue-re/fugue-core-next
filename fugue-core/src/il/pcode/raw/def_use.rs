use rustc_hash::FxHashMap;

use crate::lifter::{RawPCodeOp, Varnode};

pub struct RawPCodeDefs<'a> {
    operations: &'a [RawPCodeOp],
    definitions: FxHashMap<Varnode, Vec<usize>>,
}

impl<'a> RawPCodeDefs<'a> {
    pub fn new(operations: &'a [RawPCodeOp]) -> Self {
        let mut definitions = FxHashMap::<Varnode, Vec<usize>>::default();
        for (index, operation) in operations.iter().enumerate() {
            if let Some(output) = operation.output() {
                definitions.entry(*output).or_default().push(index);
            }
        }
        Self {
            operations,
            definitions,
        }
    }

    pub fn defining_op(
        &self,
        varnode: &Varnode,
        before: usize,
    ) -> Option<(usize, &'a RawPCodeOp)> {
        let index = *self
            .definitions
            .get(varnode)?
            .iter()
            .rev()
            .find(|&&index| index < before)?;
        Some((index, &self.operations[index]))
    }
}
