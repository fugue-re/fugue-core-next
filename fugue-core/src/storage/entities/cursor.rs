use std::ops::Bound;

pub(crate) fn cursor_bound<T>(after: Option<T>) -> Bound<T> {
    after.map_or(Bound::Unbounded, Bound::Excluded)
}

pub(crate) fn cursor_bound_or_minimum<T>(after: Option<T>, minimum: T) -> Bound<T> {
    after.map_or(Bound::Included(minimum), Bound::Excluded)
}
