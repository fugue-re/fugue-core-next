use super::IlArtefact;

pub trait IlAnalysis<I: IlArtefact>: Sized {
    fn analyse(ir: &I) -> Self;
}
