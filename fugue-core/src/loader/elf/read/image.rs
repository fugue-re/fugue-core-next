use std::ops::Range;

use object::ReadRef;

use crate::types::BytesOrMapping;

pub struct ElfImageData<'a> {
    image: BytesOrMapping<'a>,
    tail: Vec<u8>,
}

impl<'a> ElfImageData<'a> {
    pub fn new(image: BytesOrMapping<'a>) -> Self {
        Self::new_with(image, Vec::new())
    }

    pub fn new_with(image: BytesOrMapping<'a>, tail: Vec<u8>) -> Self {
        Self { image, tail }
    }

    pub fn image(&self) -> &BytesOrMapping<'a> {
        &self.image
    }

    pub fn into_image(self) -> BytesOrMapping<'a> {
        self.image
    }

    fn part(&self, range: Range<u64>) -> Option<(&[u8], Range<u64>)> {
        let image = self.image.as_ref();
        let image_len = image.len() as u64;
        if range.end <= image_len {
            Some((image, range))
        } else if range.start >= image_len {
            Some((&self.tail, range.start - image_len..range.end - image_len))
        } else {
            None
        }
    }
}

impl<'a> ReadRef<'a> for &'a ElfImageData<'_> {
    fn len(self) -> Result<u64, ()> {
        Ok((self.image.as_ref().len() + self.tail.len()) as u64)
    }

    fn read_bytes_at(self, offset: u64, size: u64) -> Result<&'a [u8], ()> {
        let (part, range) = self
            .part(offset..offset.checked_add(size).ok_or(())?)
            .ok_or(())?;
        part.read_bytes_at(range.start, size)
    }

    fn read_bytes_at_until(self, range: Range<u64>, delimiter: u8) -> Result<&'a [u8], ()> {
        let (part, range) = self.part(range).ok_or(())?;
        part.read_bytes_at_until(range, delimiter)
    }
}
