use std::collections::BTreeSet;

use super::{ECodeSsaConstruction, ECodeSsaDomains};
use crate::il::common::{FlagId, IlArtefact, IlBlockId, IlDominance, IlError, RegisterId};
use crate::il::ecode::ssa::{ECodeSsaDomain, ECodeSsaIr};
use crate::il::ecode::{ECodeExprOpcode, ECodeIr, ECodeStmt, ECodeStmtOpcode};

impl ECodeSsaDomains {
    fn record_width(&mut self, domain: ECodeSsaDomain, width: u32) -> Result<(), IlError> {
        match self.widths.get(&domain) {
            Some(existing) if *existing != width => Err(IlError::width_mismatch(ECodeSsaIr::FORM)),
            Some(_) => Ok(()),
            None => {
                self.widths.insert(domain, width);
                Ok(())
            }
        }
    }
}

impl ECodeSsaConstruction<'_, '_> {
    pub(crate) fn discover_domains(&self) -> Result<ECodeSsaDomains, IlError> {
        let mut domains = ECodeSsaDomains::default();

        for (block_index, block) in self.source.graph().blocks().iter().enumerate() {
            let block_id = IlBlockId::try_from_index(block_index)?;

            for statement_index in block.operations().start()..block.operations().end() {
                let statement = &self.source.statements()[statement_index];

                match statement.opcode() {
                    ECodeStmtOpcode::WriteRegister => {
                        let width = self.statement_value_width(statement)?;
                        let domain =
                            ECodeSsaDomain::Register(RegisterId::new(statement.immediate()));

                        domains.record_width(domain, width)?;
                        domains
                            .definitions
                            .entry(domain)
                            .or_default()
                            .push(block_id);
                    }
                    ECodeStmtOpcode::WriteFlag => {
                        let width = self.statement_value_width(statement)?;
                        let domain = ECodeSsaDomain::Flag(FlagId::new(statement.immediate()));

                        domains.record_width(domain, width)?;
                        domains
                            .definitions
                            .entry(domain)
                            .or_default()
                            .push(block_id);
                    }
                    ECodeStmtOpcode::Store => {
                        let space = statement.address_space().ok_or_else(|| {
                            IlError::missing_component(ECodeIr::FORM, "address space")
                        })?;
                        let domain = ECodeSsaDomain::Memory(space);

                        domains.record_width(domain, 0)?;
                        domains
                            .definitions
                            .entry(domain)
                            .or_default()
                            .push(block_id);
                    }
                    _ => {}
                }
            }
        }

        for expression in self.source.expressions() {
            match expression.opcode() {
                ECodeExprOpcode::ReadRegister => {
                    let domain = ECodeSsaDomain::Register(RegisterId::new(expression.immediate()));
                    domains.record_width(domain, expression.width())?;
                    domains.reads.insert(domain);
                }
                ECodeExprOpcode::ReadFlag => {
                    let domain = ECodeSsaDomain::Flag(FlagId::new(expression.immediate()));
                    domains.record_width(domain, expression.width())?;
                    domains.reads.insert(domain);
                }
                ECodeExprOpcode::Load => {
                    let space = expression.address_space().ok_or_else(|| {
                        IlError::missing_component(ECodeIr::FORM, "address space")
                    })?;

                    domains.record_width(ECodeSsaDomain::Memory(space), 0)?;
                }
                _ => {}
            }
        }

        for definitions in domains.definitions.values_mut() {
            definitions.sort();
            definitions.dedup();
        }

        Ok(domains)
    }

    fn statement_value_width(&self, statement: &ECodeStmt) -> Result<u32, IlError> {
        let value = statement
            .value()
            .ok_or_else(|| IlError::missing_component(ECodeIr::FORM, "value"))?;
        Ok(self.source.expressions()[value.index()].width())
    }

    pub(crate) fn place_block_arguments(
        &mut self,
        domains: &ECodeSsaDomains,
        dominance: &IlDominance,
    ) -> Result<(), IlError> {
        let frontiers = dominance.frontiers(
            self.source.graph().blocks(),
            self.source.graph().successors(),
        );
        let block_count = self.source.graph().blocks().len();
        let mut placed = BTreeSet::new();

        for (domain, definitions) in &domains.definitions {
            let width = domains.widths[domain];
            let placement = frontiers.place_phis(block_count, definitions.iter().copied());

            for block in placement.blocks() {
                if !placed.insert((*block, *domain)) {
                    continue;
                }

                let value = self.builder.push_block_argument_value(*block, width)?;
                self.builder.set_value_domain(value, *domain);
                self.block_argument_domains.insert(value, *domain);
                self.block_arguments[block.index()].push((*domain, value));
            }
        }

        for arguments in &mut self.block_arguments {
            arguments.sort_by_key(|(domain, _)| *domain);
        }

        Ok(())
    }
}
