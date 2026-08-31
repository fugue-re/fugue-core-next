use fugue_core::engine::Priority;
use fugue_core::ir::FlowKind;
use fugue_core::project::AnalysisPhase;

#[test]
fn phases_order_by_dependency() {
    let ordered = AnalysisPhase::ALL;

    assert_eq!(ordered[0], AnalysisPhase::Retract);
    assert_eq!(ordered[ordered.len() - 1], AnalysisPhase::Identify);

    for window in ordered.windows(2) {
        assert!(
            window[0] < window[1],
            "{} must order before {}",
            window[0],
            window[1]
        );
    }
}

#[test]
fn phase_dominates_priority_in_dispatch_order() {
    let early = (AnalysisPhase::Decode, Priority::ENRICHMENT);
    let late = (AnalysisPhase::Derive, Priority::DISCOVERY);

    assert!(
        early < late,
        "an enrichment-priority decode must still run before a discovery-priority derive"
    );
}

#[test]
fn retract_precedes_every_other_phase() {
    for phase in AnalysisPhase::ALL {
        if phase != AnalysisPhase::Retract {
            assert!(AnalysisPhase::Retract < phase);
        }
    }
}

#[test]
fn tail_call_flow_kind_is_reachable() {
    let kind = FlowKind::TailCallBranch;

    assert!(
        kind.is_global(),
        "a tail call leaves the function, so it must be a global edge"
    );
    assert_ne!(kind, FlowKind::Branch);
}
