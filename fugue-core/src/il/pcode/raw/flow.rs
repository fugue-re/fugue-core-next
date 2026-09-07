use crate::ir::{Address, Location, ToRawAddress};
use crate::lifter::{Language, Op, RawPCodeOp};

pub enum RawPCodeFlow {
    Branch(Option<Location>),
    Call(Option<Location>),
    FallThrough(Location),
    Intrinsic,
    Return(Option<Address>),
}

pub struct RawPCodeFlows<'a> {
    address: Address,
    language: &'static Language,
    operations: &'a [RawPCodeOp],
    size: usize,
}

impl<'a> RawPCodeFlows<'a> {
    pub fn new(
        language: &'static Language,
        address: Address,
        size: usize,
        operations: &'a [RawPCodeOp],
    ) -> Self {
        Self {
            address,
            language,
            operations,
            size,
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = (u16, RawPCodeFlow)> + '_ {
        let empty = self
            .operations
            .is_empty()
            .then(|| (0, RawPCodeFlow::FallThrough(self.next_location(1))));
        empty
            .into_iter()
            .chain(self.operations.iter().enumerate().flat_map(|(index, _)| {
                let index = index as u16;
                self.flows_for(index).map(move |flow| (index, flow))
            }))
    }

    pub fn flows_for(&self, index: u16) -> impl Iterator<Item = RawPCodeFlow> + '_ {
        let flows = if self.operations.is_empty() {
            [
                (index == 0).then(|| RawPCodeFlow::FallThrough(self.next_location(1))),
                None,
            ]
        } else if let Some(operation) = self.operations.get(usize::from(index)) {
            let next = self.next_location(index + 1);
            let inputs = operation.inputs();

            match operation.op() {
                Op::Branch => [
                    Some(RawPCodeFlow::Branch(Location::absolute_from(
                        self.language,
                        self.address,
                        inputs[0],
                        index,
                    ))),
                    None,
                ],
                Op::CBranch => [
                    Some(RawPCodeFlow::Branch(Location::absolute_from(
                        self.language,
                        self.address,
                        inputs[0],
                        index,
                    ))),
                    Some(RawPCodeFlow::FallThrough(next)),
                ],
                Op::IBranch => [Some(RawPCodeFlow::Branch(None)), None],
                Op::Call => [
                    Some(RawPCodeFlow::Call(Location::absolute_from(
                        self.language,
                        self.address,
                        inputs[0],
                        index,
                    ))),
                    Some(RawPCodeFlow::FallThrough(next)),
                ],
                Op::ICall => [
                    Some(RawPCodeFlow::Call(None)),
                    Some(RawPCodeFlow::FallThrough(next)),
                ],
                Op::Return => {
                    let return_address = inputs[0]
                        .to_address(self.language)
                        .map(|address| Address::new(self.address.space(), address));
                    [Some(RawPCodeFlow::Return(return_address)), None]
                }
                Op::UserOp(_, _) => [
                    Some(RawPCodeFlow::Intrinsic),
                    Some(RawPCodeFlow::FallThrough(next)),
                ],
                _ if index + 1 == self.operations.len() as u16 => {
                    [Some(RawPCodeFlow::FallThrough(next)), None]
                }
                _ => [None, None],
            }
        } else {
            [None, None]
        };

        flows.into_iter().flatten()
    }

    fn next_location(&self, index: u16) -> Location {
        let operation_count = self.operations.len() as u16;
        if index >= operation_count {
            Location::new(self.address + self.size, index - operation_count)
        } else {
            Location::new(self.address, index)
        }
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
