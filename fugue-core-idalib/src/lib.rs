use fallible_iterator::FallibleIterator;

use fugue_base::arch::Arch;
use fugue_base::lifter::{Language, Lifter, LifterBuilder};
use fugue_base::loader::{Loadable, LoadableFromFile, LoadableSegment, LoaderError};
use fugue_base::memory::SegmentProperties;
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

        for (_, segm) in self.database.segments() {
            start = start.min(segm.start_address().into());
            end = end.max(segm.end_address().wrapping_sub(1).into());
        }

        (start, end)
    }

    fn segments<'a>(
        &'a self,
    ) -> impl FallibleIterator<Item = LoadableSegment<'a>, Error = LoaderError> + 'a {
        // NOTE: we take all segments verbatim from IDA except the extern segment; we
        // opt to patch each entry with the architecture's "external function template",
        // which amounts to a return instruction, and hence fits in the space available
        // for all architectures we support.

        let address_size = self.lifter.address_size();

        fallible_iterator::convert(self.database.segments().map(move |(_, segm)| {
            let start = Address::from(segm.start_address());
            let end = Address::from(segm.end_address().wrapping_sub(1));

            tracing::trace!("loading segment {start}-{end}");

            let name = segm.name().unwrap_or_else(|| String::from("LOAD"));
            let permissions = segm.permissions();
            let type_ = segm.r#type();

            let mut properties = SegmentProperties::default();

            if permissions.is_readable() {
                properties |= SegmentProperties::PERM_READ;
            }

            if permissions.is_writable() {
                properties |= SegmentProperties::PERM_WRITE;
            }

            if permissions.is_executable() {
                properties |= SegmentProperties::PERM_EXECUTE;
            }

            if type_.is_bss() {
                properties |= SegmentProperties::UNINITIALISED;
            }

            let mut bytes = segm.bytes();

            if type_.is_extern() {
                properties |= SegmentProperties::EXTERNAL;

                let template = self.architecture.external_thunk_template();
                let template_len = template.len();
                let aligned_template_len =
                    template_len.next_multiple_of(address_size);

                if aligned_template_len > address_size {
                    tracing::warn!("external thunk template is larger than available space in extern segment; skipping");
                } else {
                    tracing::trace!("patching extern segment with external thunk template");
                    for chunk in bytes.chunks_exact_mut(aligned_template_len) {
                        chunk[..template_len].copy_from_slice(template.bytes());
                    }
                }
            }

            Ok(LoadableSegment::from_parts(name, start, properties, segm.bytes()))
        }))
    }
}
