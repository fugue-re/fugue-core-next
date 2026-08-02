use crate::ir::{Address, Insn, InsnTarget};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FlowTargets {
    targets: Vec<FlowTarget>,
}

impl FlowTargets {
    pub fn new(targets: impl Into<Vec<FlowTarget>>) -> Self {
        Self {
            targets: targets.into(),
        }
    }

    pub fn targets(&self) -> &[FlowTarget] {
        &self.targets
    }
}

#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
pub enum FlowKind {
    Branch,
    Call,
    CBranch,
    Fall,
    IBranch,
    ICall,
    Return,
    ServiceCall,
    SwitchBranch,
    SwitchCall,
    TailCallBranch,
}

impl FlowKind {
    pub fn from_insn_target(insn: &Insn, target: &InsnTarget) -> Option<Self> {
        use InsnTarget::*;

        let kind = match target {
            IntraBlk(target, false) if target.position() == 0 => {
                if insn.has_fall_through() {
                    Self::CBranch
                } else {
                    Self::Branch
                }
            }
            IntraBlk(target, true) if target.position() == 0 => Self::Fall,
            InterBlk(_) => {
                if insn.has_fall_through() {
                    Self::CBranch
                } else {
                    Self::Branch
                }
            }
            InterSub(target) => {
                if target.is_some() {
                    Self::Call
                } else {
                    Self::ICall
                }
            }
            InterRet(_, _) => Self::Return,
            Intrinsic => Self::ServiceCall,
            _ => {
                return None;
            }
        };
        Some(kind)
    }

    pub fn is_branch(&self) -> bool {
        matches!(self, Self::Branch | Self::CBranch | Self::IBranch)
    }

    pub fn is_call(&self) -> bool {
        matches!(
            self,
            Self::Call | Self::ICall | Self::ServiceCall | Self::SwitchCall | Self::TailCallBranch
        )
    }

    pub fn is_conditional(&self) -> bool {
        matches!(self, Self::CBranch)
    }

    pub fn is_fall_through(&self) -> bool {
        matches!(self, Self::Fall)
    }

    pub fn is_global(&self) -> bool {
        self.is_call() || self.is_return()
    }

    pub fn is_indirect(&self) -> bool {
        matches!(self, Self::ICall | Self::IBranch)
    }

    pub fn is_return(&self) -> bool {
        matches!(self, Self::Return)
    }

    pub fn is_switch(&self) -> bool {
        matches!(self, Self::SwitchBranch | Self::SwitchCall)
    }
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
pub struct FlowTarget {
    from: Address,
    to: Address,
    kind: FlowKind,
}

impl FlowTarget {
    pub fn new(from: impl Into<Address>, to: impl Into<Address>, kind: FlowKind) -> Self {
        FlowTarget {
            from: from.into(),
            to: to.into(),
            kind,
        }
    }

    pub fn from_insn_target(
        insn: &Insn,
        target: &InsnTarget,
        to: impl Into<Address>,
    ) -> Option<Self> {
        let kind = FlowKind::from_insn_target(insn, target)?;
        Some(Self::new(insn.address(), to.into(), kind))
    }

    pub fn from(&self) -> Address {
        self.from
    }

    pub fn to(&self) -> Address {
        self.to
    }

    pub fn kind(&self) -> FlowKind {
        self.kind
    }
}
