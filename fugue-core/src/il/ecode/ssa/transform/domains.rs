use std::collections::{BTreeMap, BTreeSet};

use super::{SsaConstruction, SsaDomain, SsaDomains};
use crate::il::common::{IlBlockId, IlDominance, IlError, IlLevel};
use crate::il::ecode::{ECodeExprOpcode, ECodeStmt, ECodeStmtOpcode};
use crate::il::pcode::{FlagId, RegisterId};

impl SsaConstruction<'_, '_> {
    pub(crate) fn discover_domains(&self) -> Result<SsaDomains, IlError> {
        let mut domains = SsaDomains::default();

        for (block_index, block) in self.source.graph().blocks().iter().enumerate() {
            let block_id = IlBlockId::try_from_index(block_index)?;

            for statement_index in block.operations().start()..block.operations().end() {
                let statement = &self.source.statements()[statement_index];

                match statement.opcode() {
                    ECodeStmtOpcode::WriteRegister => {
                        let width = self.statement_value_width(statement)?;
                        let domain = SsaDomain::Register(RegisterId::new(statement.immediate()));

                        Self::record_domain_width(&mut domains.widths, domain, width)?;
                        domains
                            .definitions
                            .entry(domain)
                            .or_default()
                            .push(block_id);
                    }
                    ECodeStmtOpcode::WriteFlag => {
                        let width = self.statement_value_width(statement)?;
                        let domain = SsaDomain::Flag(FlagId::new(statement.immediate()));

                        Self::record_domain_width(&mut domains.widths, domain, width)?;
                        domains
                            .definitions
                            .entry(domain)
                            .or_default()
                            .push(block_id);
                    }
                    ECodeStmtOpcode::Store => {
                        let space = statement
                            .address_space()
                            .ok_or(IlError::missing_component(IlLevel::ECode, "address space"))?;
                        let domain = SsaDomain::Memory(space);

                        Self::record_domain_width(&mut domains.widths, domain, 0)?;
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
                    let domain = SsaDomain::Register(RegisterId::new(expression.immediate()));
                    Self::record_domain_width(&mut domains.widths, domain, expression.width())?;
                    domains.reads.insert(domain);
                }
                ECodeExprOpcode::ReadFlag => {
                    let domain = SsaDomain::Flag(FlagId::new(expression.immediate()));
                    Self::record_domain_width(&mut domains.widths, domain, expression.width())?;
                    domains.reads.insert(domain);
                }
                ECodeExprOpcode::Load => {
                    let space = expression
                        .address_space()
                        .ok_or(IlError::missing_component(IlLevel::ECode, "address space"))?;

                    Self::record_domain_width(&mut domains.widths, SsaDomain::Memory(space), 0)?;
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
            .ok_or(IlError::missing_component(IlLevel::ECode, "value"))?;
        Ok(self.source.expressions()[value.index()].width())
    }

    fn record_domain_width(
        widths: &mut BTreeMap<SsaDomain, u32>,
        domain: SsaDomain,
        width: u32,
    ) -> Result<(), IlError> {
        if let Some(existing) = widths.get(&domain) {
            if *existing != width {
                return Err(IlError::width_mismatch(IlLevel::ECodeSsa));
            }
        } else {
            widths.insert(domain, width);
        }

        Ok(())
    }

    pub(crate) fn place_block_arguments(
        &mut self,
        domains: &SsaDomains,
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
