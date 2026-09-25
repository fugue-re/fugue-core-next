use super::IlArtefact;

pub trait IlRewrite<I: IlArtefact> {
    fn rewrite(&mut self, ir: &mut I);
}

impl<I, R> IlRewrite<I> for &mut R
where
    I: IlArtefact,
    R: IlRewrite<I> + ?Sized,
{
    fn rewrite(&mut self, ir: &mut I) {
        R::rewrite(self, ir);
    }
}
