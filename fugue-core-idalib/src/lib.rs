use fallible_iterator::FallibleIterator;

use fugue_base::arch::Arch;
use fugue_base::lifter::{Language, Lifter, LifterBuilder};
use fugue_base::loader::{Loadable, LoadableFromFile, LoadableSegment, LoaderError};
use fugue_base::types::{Address, AttributeMap};

use idalib::idb::IDB;

pub struct IDABinary {
    database: IDB,
    architecture: Arch,
    lifter: Lifter,
    attributes: AttributeMap,
}

impl LoadableFromFile for IDABinary {
    fn from_file_with(
        path: impl AsRef<std::path::Path>,
        attributes: impl Into<AttributeMap>,
    ) -> Result<Self, LoaderError>
    where
        Self: Sized,
    {
        let path = path.as_ref();
        let attributes = attributes.into();

        // NOTE: we likely want to add an API to tell IDA where to store the database...
        let database = IDB::open_with(path, true, false).map_err(LoaderError::other)?;
        let processor = database.processor();

        let is_32 = database.meta().is_32bit_exactly();
        let is_64 = database.meta().is_64bit();

        if !is_32 && !is_64 {
            return Err(LoaderError::UnsupportedArch);
        }

        let builder = if processor.family().is_arm() {
            if is_64 {
                LifterBuilder::new("AARCH64").bits(64)
            } else if matches!(database.meta().start_address(), Some(addr) if processor.is_thumb_at(addr))
            {
                LifterBuilder::new("ARM").bits(32).variant("v8T")
            } else {
                LifterBuilder::new("ARM").bits(32)
            }
        } else if processor.family().is_386() {
            if is_64 {
                LifterBuilder::new("x86").bits(64)
            } else {
                LifterBuilder::new("x86").bits(32)
            }
        } else {
            return Err(LoaderError::UnsupportedArch);
        };

        let lifter = builder.build().map_err(LoaderError::other)?;
        let architecture = Arch::new(lifter.language());

        Ok(IDABinary {
            database,
            architecture,
            lifter,
            attributes,
        })
    }
}

impl Loadable for IDABinary {
    fn attributes(&self) -> &AttributeMap {
        &self.attributes
    }

    fn attributes_mut(&mut self) -> &mut AttributeMap {
        &mut self.attributes
    }

    fn entry(&self) -> Option<Address> {
        self.database.meta().start_address().map(Address::from)
    }

    fn language(&self) -> &'static Language {
        self.lifter.language()
    }

    fn lifter(&self) -> Lifter {
        self.lifter.clone()
    }

    fn segment_range(&self) -> (Address, Address) {
        let mut start = Address::MAX;
        let mut end = Address::zero();

        let mut extern_segm = None;

        for (_, segm) in self.database.segments() {
            start = start.min(segm.start_address().into());
            // NOTE: we use inclusive ranges
            end = end.max(segm.end_address().wrapping_sub(1).into());

            if segm.r#type().is_extern() {
                extern_segm = Some(segm);
            }
        }

        // If we have an extern segment, to avoid having to deal with arbitrary relocations we
        // create a new segment that maps the original extern segment pointers. We can calculate
        // the size of this segment by dividing the size of the original segment by the address
        // size.
        if let Some(extern_segm) = extern_segm {
            let count = (extern_segm.end_address() - extern_segm.start_address()) as usize
                / self.lifter.address_size();
            end += count * self.architecture.external_thunk_template().len();
        }

        (start, end)
    }

    fn segments<'a>(
        &'a self,
    ) -> impl FallibleIterator<Item = LoadableSegment<'a>, Error = LoaderError> + 'a {
        fallible_iterator::empty()
    }
}
