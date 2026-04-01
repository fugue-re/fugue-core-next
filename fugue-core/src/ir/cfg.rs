use crate::ir::{Insn, InsnTarget, MetaAddress};

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FlowKind {
    Branch,
    CBranch,
    IBranch,
    Call,
    ICall,
    ServiceCall,
    Return,
    Fall,
    SwitchBranch,
    SwitchCall,
    TailCallBranch,
}

impl FlowKind {
    pub fn from_insn_target(insn: &Insn, target: &InsnTarget) -> Option<Self> {
        use InsnTarget::*;

        let kind = match target {
            IntraBlk(target, false) if target.position() == 0 => {
                if insn.has_fall() {
                    Self::CBranch
                } else {
                    Self::Branch
                }
            }
            IntraBlk(target, true) if target.position() == 0 => Self::Fall,
            InterBlk(_) => {
                if insn.has_fall() {
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

    pub fn is_fall(&self) -> bool {
        matches!(self, Self::Fall)
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FlowTarget {
    from: MetaAddress,
    to: MetaAddress,
    kind: FlowKind,
}

impl FlowTarget {
    pub fn new(from: impl Into<MetaAddress>, to: impl Into<MetaAddress>, kind: FlowKind) -> Self {
        FlowTarget {
            from: from.into(),
            to: to.into(),
            kind,
        }
    }

    pub fn from_insn_target(
        insn: &Insn,
        target: &InsnTarget,
        to: impl Into<MetaAddress>,
    ) -> Option<Self> {
        let kind = FlowKind::from_insn_target(insn, target)?;
        Some(Self::new(insn.address(), to.into(), kind))
    }

    pub fn from(&self) -> MetaAddress {
        self.from
    }

    pub fn to(&self) -> MetaAddress {
        self.to
    }

    pub fn kind(&self) -> FlowKind {
        self.kind
    }
}
