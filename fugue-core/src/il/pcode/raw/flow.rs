use smallvec::SmallVec;

use crate::ir::{Address, Location, ToRawAddress};
use crate::lifter::{Language, Op, RawPCodeOp};

pub enum RawPCodeFlow {
    Branch(Option<Location>),
    Call(Option<Location>),
    FallThrough(Location),
    Intrinsic,
    Return(Option<Address>),
}

pub struct RawPCodeFlows {
    targets: SmallVec<[(u16, RawPCodeFlow); 2]>,
}

impl RawPCodeFlows {
    pub fn new(
        language: &'static Language,
        address: Address,
        size: usize,
        operations: &[RawPCodeOp],
    ) -> Self {
        let operation_count = operations.len() as u16;
        let next_address = address + size;

        let next_location = |index: u16| -> Location {
            if index >= operation_count {
                Location::new(next_address, index - operation_count)
            } else {
                Location::new(address, index)
            }
        };

        let mut targets = SmallVec::new();

        if operation_count == 0 {
            targets.push((0, RawPCodeFlow::FallThrough(next_location(1))));
            return Self { targets };
        }

        for (index, operation) in operations.iter().enumerate() {
            let index = index as u16;
            let next = next_location(index + 1);
            let inputs = operation.inputs();

            match operation.op() {
                Op::Branch => {
                    let location = Location::absolute_from(language, address, inputs[0], index);
                    targets.push((index, RawPCodeFlow::Branch(location)));
                }
                Op::CBranch => {
                    let location = Location::absolute_from(language, address, inputs[0], index);
                    targets.push((index, RawPCodeFlow::Branch(location)));
                    targets.push((index, RawPCodeFlow::FallThrough(next)));
                }
                Op::IBranch => {
                    targets.push((index, RawPCodeFlow::Branch(None)));
                }
                Op::Call => {
                    let location = Location::absolute_from(language, address, inputs[0], index);
                    targets.push((index, RawPCodeFlow::Call(location)));
                    targets.push((index, RawPCodeFlow::FallThrough(next)));
                }
                Op::ICall => {
                    targets.push((index, RawPCodeFlow::Call(None)));
                    targets.push((index, RawPCodeFlow::FallThrough(next)));
                }
                Op::Return => {
                    let return_address = inputs[0]
                        .to_address(language)
                        .map(|address_offset| Address::new(address.space(), address_offset));
                    targets.push((index, RawPCodeFlow::Return(return_address)));
                }
                Op::UserOp(_, _) => {
                    targets.push((index, RawPCodeFlow::Intrinsic));
                    targets.push((index, RawPCodeFlow::FallThrough(next)));
                }
                _ => {
                    if index + 1 == operation_count {
                        targets.push((index, RawPCodeFlow::FallThrough(next)));
                    }
                }
            }
        }

        Self { targets }
    }

    pub fn iter(&self) -> impl Iterator<Item = (u16, &RawPCodeFlow)> + '_ {
        self.targets.iter().map(|(index, flow)| (*index, flow))
    }

    pub fn flow_for(&self, index: u16) -> Option<&RawPCodeFlow> {
        self.targets
            .iter()
            .find(|(target_index, _)| *target_index == index)
            .map(|(_, flow)| flow)
    }
}

pub(crate) fn remap_target_position(
    operations: &[RawPCodeOp],
    address: Address,
    target: Location,
) -> Option<Location> {
    if target.address() != address {
        return Some(target);
    }

    let raw_target = usize::from(target.position());
    let mut raw_index = 0usize;
    let mut semantic_index = 0u16;

    while raw_index < raw_target {
        let operation = operations.get(raw_index)?;
        raw_index += operation.spill() + 1;
        semantic_index = semantic_index.checked_add(1)?;
    }

    (raw_index == raw_target).then(|| Location::new(target.address(), semantic_index))
}
