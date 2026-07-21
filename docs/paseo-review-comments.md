# Paseo review comments

Base: `feature/dialects`

1. `fugue-core/src/analysis/function/recovery/analysis.rs:new:601`

   What is this and why is it here?

   ```rust
   fn switch_would_downgrade(project: &Project, branch: Address, candidate: &Switch) -> bool {
       if candidate.is_override() || candidate.is_assisted() {
           return false;
       }
   ```

2. `fugue-core/src/analysis/function/recovery/analysis.rs:new:644`

   This is not running in the switch recovery pass.

   ```rust
   .add_switch(branch, move |id, _| {
       switch.with_id(id).with_function(function_id)
   })
   .map_err(|e| AnalysisError::pass_failed("switch-recovery", e))?;
   ```

3. `fugue-core/src/analysis/function/recovery/ir.rs:new:180`

   `mem::take`

   ```rust
   pub fn take_pending_switches(&mut self) -> Vec<Switch> {
       std::mem::take(&mut self.pending_switches)
   }
   ```

4. `fugue-core/src/analysis/function/recovery/ir.rs:new:284`

   Do the other lifting methods become superfluous now? Do they actually work as intended?

   ```rust
   pub fn lift_block_into(
       &self,
       id: usize,
       reader: &mut SegmentReader,
   ```

5. `fugue-core/src/analysis/non_returning/mod.rs:new:7`

   This should use our `Symbol` type?

   ```rust
   pub struct NonReturningExterns {
       name: &'static str,
       names: &'static [&'static str],
   }
   ```

6. `fugue-core/src/analysis/non_returning/mod.rs:new:1`

   These are platform analyses, so they belong under `platform/...`.

   ```rust
   mod posix;
   mod windows;
   ```

7. `fugue-core/src/analysis/switch/analysis.rs:new:42`

   Why does this belong here? I have no doubt that we may need this kind of abstraction elsewhere--so why are you adding it only here? It should be in a place for reuse.

   ```rust
   struct LocalSsaBuild {
       ssa: Option<ECodeSsaIr>,
       omitted_blocks: BTreeSet<Address>,
   }
   ```

8. `fugue-core/src/analysis/switch/analysis.rs:new:70`

   All of the methods here need to be reviewed for utility and consistency. I believe we have far too many types and helpers across the switch modules. It's incomprehensible.

   ```rust
   fn resolve_indirect_branches(
       function: &PartialFunction,
       reader: &mut SegmentReader,
       translator: &mut Translator,
   ```

9. `fugue-core/src/analysis/value/strided.rs:new:7`

   `StridedIntervalRepr`

   ```rust
   pub struct StridedInterval(Repr);

   enum Repr {
       Empty(u32),
       Interval {
   ```

10. `fugue-core/src/storage/segments/mod.rs:new:1617`

    `segment_properties_by_space`? Take a look at the other APIs in this module and make it consistent.

    ```rust
    pub fn space_segment_properties(
        &self,
        space_id: AddressSpaceId,
        at: Address,
    ```
