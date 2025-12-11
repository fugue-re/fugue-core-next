use crate::constructor::Constructor;
use crate::pcode::LiftingContextState;
use crate::ConstructorResolver;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionNode {
    pub start_bit: u32,
    pub size: u32,
    pub context_decision: bool,
    pub patterns: &'static [DecisionPair],
    pub children: &'static [usize],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionPair {
    pub constructor: &'static Constructor,
    pub pattern: DisjointPattern,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisjointPattern {
    Context(Pattern),
    Instruction(Pattern),
    Combine {
        context: Pattern,
        instruction: Pattern,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern {
    pub offset: usize,
    pub non_zero_size: Option<usize>,
    pub masks: &'static [u32],
    pub values: &'static [u32],
}

impl DecisionNode {
    pub fn resolve<R: ConstructorResolver>(
        &self,
        input: &mut LiftingContextState,
    ) -> Option<&'static Constructor> {
        let mut curr = self;

        // traverse down the tree until we hit a leaf
        while curr.size != 0 {
            let start_bit = curr.start_bit;
            let size = curr.size;

            let index = if curr.context_decision {
                input.inputs.input.context_bits(start_bit as _, size as _)
            } else {
                unsafe {
                    input
                        .inputs
                        .input
                        .instruction_bits(start_bit as _, size as _)?
                }
            };

            curr = &R::DECISION_TREES[*curr.children.get(index as usize)?];
        }

        // size is 0, we are at a leaf
        for pattern in curr.patterns.iter() {
            if pattern.matches(input) {
                return Some(pattern.constructor());
            }
        }

        None
    }
}

impl DecisionPair {
    pub fn matches(&self, input: &mut LiftingContextState) -> bool {
        match &self.pattern {
            DisjointPattern::Context(pat) => pat.matches_context(input),
            DisjointPattern::Instruction(pat) => pat.matches_instruction(input),
            DisjointPattern::Combine {
                context,
                instruction,
            } => context.matches_context(input) && instruction.matches_instruction(input),
        }
    }

    pub fn constructor(&self) -> &'static Constructor {
        self.constructor
    }
}

impl Pattern {
    const ALWAYS_TRUE: Option<usize> = Some(0);
    const ALWAYS_FALSE: Option<usize> = None;

    pub fn matches_context(&self, input: &mut LiftingContextState) -> bool {
        self.matches(
            |input, offset, size| Some(input.inputs.input.context_bytes(offset, size)),
            input,
        )
    }

    pub fn matches_instruction(&self, input: &mut LiftingContextState) -> bool {
        self.matches(
            |input, offset, size| unsafe { input.inputs.input.instruction_bytes(offset, size) },
            input,
        )
    }

    fn matches(
        &self,
        get_bytes: impl Fn(&mut LiftingContextState, usize, usize) -> Option<u32>,
        input: &mut LiftingContextState,
    ) -> bool {
        if self.non_zero_size == Self::ALWAYS_TRUE {
            return true;
        }

        if self.non_zero_size == Self::ALWAYS_FALSE {
            return false;
        }

        for (i, (&mask, &value)) in self.masks.iter().zip(self.values.iter()).enumerate() {
            let offset = self.offset + i * size_of::<u32>();
            let Some(bytes) = get_bytes(input, offset, size_of::<u32>()) else {
                return false;
            };
            if (bytes & mask) != value {
                return false;
            }
        }

        true
    }
}
