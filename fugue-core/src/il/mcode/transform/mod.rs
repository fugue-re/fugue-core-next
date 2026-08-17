use self::lifter::ECodeToMCodeLifter;
use crate::analysis::control::CancellationToken;
use crate::arch::Arch;
use crate::il::common::{
    IlArtefact, IlError, IlGenerationContext, IlGenerationError, IlGraph, IlMetadata,
    IlTransformer, IlValueId, RegisterBank,
};
use crate::il::ecode::ECodeIr;
use crate::il::mcode::recovery::{
    MCodeAliasOverride, MCodeAliasOverrides, MCodeRecovery, MCodeRecoveryConfig,
};
use crate::il::mcode::{MCodeBuilder, MCodeFunctionFacts, MCodeIr, MCodeOptimiser, MCodeVar};
use crate::platform::Platform;

mod lifter;
mod variables;

#[derive(Debug, Default)]
pub struct ECodeToMCode {
    scratch: ECodeToMCodeScratch,
    overrides: MCodeAliasOverrides,
}

#[derive(Debug, Default)]
struct ECodeToMCodeScratch {
    operands: Vec<IlValueId>,
    required_values: Vec<IlValueId>,
}

impl ECodeToMCode {
    pub fn transform(
        &mut self,
        ir: &ECodeIr,
        arch: &Arch,
        platform: &Platform,
        facts: Option<&MCodeFunctionFacts>,
        cancellation: &CancellationToken,
    ) -> Result<MCodeIr, IlError> {
        cancellation.check()?;

        let language = arch.language();
        let registers = RegisterBank::new(language)?;
        let convention = language
            .convention(platform.compiler_spec_id())
            .or_else(|| language.convention("default"))
            .ok_or_else(|| IlError::missing_component(MCodeIr::FORM, "calling convention"))?;
        let preserved = registers.call_preserved_registers(platform.compiler_spec_id())?;
        let config = MCodeRecoveryConfig::from_convention(&registers, convention, preserved)?;
        let config = match facts {
            Some(facts) => config.with_call_facts(facts),
            None => config,
        }
        .with_alias_overrides(&self.overrides);
        let recovery = MCodeRecovery::new(ir, &config, &registers)?;

        self.scratch.required_values.clear();
        let metadata = IlMetadata::new(
            ir.metadata().function(),
            ir.metadata().input_revision(),
        );
        let builder = MCodeBuilder::new(metadata, IlGraph::default());
        let mut mcode = ECodeToMCodeLifter::new(ir, &recovery, builder, &mut self.scratch)?
            .lift(cancellation)?;
        #[cfg(debug_assertions)]
        {
            mcode
                .verify()
                .expect("unoptimised MCode fails verification");
        }
        mcode.rewrite(MCodeOptimiser::new(&self.scratch.required_values));

        Ok(mcode)
    }

    pub fn force_aliased(&mut self, variable: MCodeVar) {
        self.overrides.insert(variable, MCodeAliasOverride::Aliased);
    }

    pub fn force_unaliased(&mut self, variable: MCodeVar) {
        self.overrides
            .insert(variable, MCodeAliasOverride::Unaliased);
    }

    pub fn clear_alias_override(&mut self, variable: MCodeVar) {
        self.overrides.remove(variable);
    }
}

impl IlTransformer for ECodeToMCode {
    type Input = ECodeIr;
    type Output = MCodeIr;

    fn transform(
        &mut self,
        source: &Self::Input,
        context: &IlGenerationContext<'_>,
        cancellation: &CancellationToken,
    ) -> Result<Self::Output, IlGenerationError> {
        let mcode = ECodeToMCode::transform(
            self,
            source,
            context.arch(),
            context.platform(),
            None,
            cancellation,
        )?;

        #[cfg(debug_assertions)]
        if !context.is_speculative() {
            mcode
                .verify()
                .expect("transformed MCode fails verification");
        }

        Ok(mcode)
    }
}

#[cfg(test)]
mod test;
