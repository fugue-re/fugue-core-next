use crate::dynamic::install::Install;
use crate::template::Op;

#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub(crate) struct ConstructTpl {
    pub(crate) delay_slot: u8,
    pub(crate) labels: u8,
    pub(crate) result: Option<u16>,
    pub(crate) operations: Box<[u16]>,
}

impl Install for ConstructTpl {
    type Target = crate::template::ConstructTpl;

    fn install(self) -> Self::Target {
        let Self {
            delay_slot,
            labels,
            result,
            operations,
        } = self;
        Self::Target {
            delay_slot,
            labels,
            result,
            operations: operations.install(),
        }
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub(crate) struct OpTpl {
    pub(crate) op: Op,
    pub(crate) inputs: Box<[u16]>,
    pub(crate) output: Option<u16>,
}

impl Install for OpTpl {
    type Target = crate::template::OpTpl;

    fn install(self) -> Self::Target {
        let Self { op, inputs, output } = self;
        Self::Target {
            op,
            inputs: inputs.install(),
            output,
        }
    }
}
