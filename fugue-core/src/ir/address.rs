use std::fmt::{Debug, Display, LowerHex, UpperHex};
use std::ops::{Add, AddAssign, RangeBounds, RangeInclusive, Sub, SubAssign};

use bincode::{Decode, Encode};
use range_set_blaze::{RangeMapBlaze, RangeSetBlaze};
use serde::{Deserialize, Serialize};

use crate::il::pcode::Varnode;
use crate::lifter::{ContextSet, Language};
use crate::storage::segments::space::AddressSpaceId;
use crate::types::Confidence;

#[derive(
    Copy,
    Clone,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Decode,
    Encode,
    Deserialize,
    Serialize,
)]
#[repr(transparent)]
pub struct Address(u64);

impl Debug for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl LowerHex for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        LowerHex::fmt(&self.0, f)
    }
}

impl UpperHex for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        UpperHex::fmt(&self.0, f)
    }
}

impl AsRef<Address> for Address {
    fn as_ref(&self) -> &Address {
        self
    }
}

impl AsRef<u64> for Address {
    fn as_ref(&self) -> &u64 {
        &self.0
    }
}

impl PartialEq<u8> for Address {
    fn eq(&self, other: &u8) -> bool {
        self.0 == *other as u64
    }
}

impl PartialEq<u16> for Address {
    fn eq(&self, other: &u16) -> bool {
        self.0 == *other as u64
    }
}

impl PartialEq<u32> for Address {
    fn eq(&self, other: &u32) -> bool {
        self.0 == *other as u64
    }
}

impl PartialEq<u64> for Address {
    fn eq(&self, other: &u64) -> bool {
        self.0 == *other
    }
}

impl PartialEq<Address> for u8 {
    fn eq(&self, other: &Address) -> bool {
        *self as u64 == other.0
    }
}

impl PartialEq<Address> for u16 {
    fn eq(&self, other: &Address) -> bool {
        *self as u64 == other.0
    }
}

impl PartialEq<Address> for u32 {
    fn eq(&self, other: &Address) -> bool {
        *self as u64 == other.0
    }
}

impl PartialEq<Address> for u64 {
    fn eq(&self, other: &Address) -> bool {
        *self == other.0
    }
}

impl From<i32> for Address {
    fn from(v: i32) -> Self {
        Self(v as u64)
    }
}

impl From<u64> for Address {
    fn from(v: u64) -> Self {
        Self(v)
    }
}

impl From<u32> for Address {
    fn from(v: u32) -> Self {
        Self(v as u64)
    }
}

impl From<u16> for Address {
    fn from(v: u16) -> Self {
        Self(v as u64)
    }
}

impl From<u8> for Address {
    fn from(v: u8) -> Self {
        Self(v as u64)
    }
}

impl From<Address> for usize {
    fn from(t: Address) -> Self {
        t.0 as _
    }
}

impl From<&'_ Address> for usize {
    fn from(t: &'_ Address) -> Self {
        t.0 as _
    }
}

impl From<Address> for u64 {
    fn from(t: Address) -> Self {
        t.0 as _
    }
}

impl From<&'_ Address> for u64 {
    fn from(t: &'_ Address) -> Self {
        t.0 as _
    }
}

impl From<Address> for u32 {
    fn from(t: Address) -> Self {
        t.0 as _
    }
}

impl From<&'_ Address> for u32 {
    fn from(t: &'_ Address) -> Self {
        t.0 as _
    }
}

impl From<Address> for u16 {
    fn from(t: Address) -> Self {
        t.0 as _
    }
}

impl From<&'_ Address> for u16 {
    fn from(t: &'_ Address) -> Self {
        t.0 as _
    }
}

impl From<Address> for u8 {
    fn from(t: Address) -> Self {
        t.0 as _
    }
}

impl From<&'_ Address> for u8 {
    fn from(t: &'_ Address) -> Self {
        t.0 as _
    }
}

impl Add<Address> for Address {
    type Output = Self;

    fn add(self, rhs: Address) -> Self {
        Self(self.0.wrapping_add(rhs.0))
    }
}

impl Sub<Address> for Address {
    type Output = Self;

    fn sub(self, rhs: Address) -> Self {
        Self(self.0.wrapping_sub(rhs.0))
    }
}

impl Add<&'_ Address> for Address {
    type Output = Self;

    fn add(self, rhs: &Address) -> Self {
        Self(self.0.wrapping_add(rhs.0))
    }
}

impl Sub<&'_ Address> for Address {
    type Output = Self;

    fn sub(self, rhs: &Address) -> Self {
        Self(self.0.wrapping_sub(rhs.0))
    }
}

impl Add<usize> for Address {
    type Output = Self;

    fn add(self, rhs: usize) -> Self {
        Self(self.0.wrapping_add(rhs as u64))
    }
}

impl Sub<usize> for Address {
    type Output = Self;

    fn sub(self, rhs: usize) -> Self {
        Self(self.0.wrapping_sub(rhs as u64))
    }
}

impl Add<u64> for Address {
    type Output = Self;

    fn add(self, rhs: u64) -> Self {
        Self(self.0.wrapping_add(rhs))
    }
}

impl Sub<u64> for Address {
    type Output = Self;

    fn sub(self, rhs: u64) -> Self {
        Self(self.0.wrapping_sub(rhs))
    }
}

impl Add<u32> for Address {
    type Output = Self;

    fn add(self, rhs: u32) -> Self {
        Self(self.0.wrapping_add(rhs as u64))
    }
}

impl Sub<u32> for Address {
    type Output = Self;

    fn sub(self, rhs: u32) -> Self {
        Self(self.0.wrapping_sub(rhs as u64))
    }
}

impl AddAssign<Address> for Address {
    fn add_assign(&mut self, rhs: Address) {
        self.0 = self.0.wrapping_add(rhs.0)
    }
}

impl SubAssign<Address> for Address {
    fn sub_assign(&mut self, rhs: Address) {
        self.0 = self.0.wrapping_sub(rhs.0)
    }
}

impl AddAssign<&'_ Address> for Address {
    fn add_assign(&mut self, rhs: &'_ Address) {
        self.0 = self.0.wrapping_add(rhs.0)
    }
}

impl SubAssign<&'_ Address> for Address {
    fn sub_assign(&mut self, rhs: &'_ Address) {
        self.0 = self.0.wrapping_sub(rhs.0)
    }
}

impl AddAssign<usize> for Address {
    fn add_assign(&mut self, rhs: usize) {
        self.0 = self.0.wrapping_add(rhs as u64)
    }
}

impl SubAssign<usize> for Address {
    fn sub_assign(&mut self, rhs: usize) {
        self.0 = self.0.wrapping_sub(rhs as u64)
    }
}

impl AddAssign<u64> for Address {
    fn add_assign(&mut self, rhs: u64) {
        self.0 = self.0.wrapping_add(rhs)
    }
}

impl SubAssign<u64> for Address {
    fn sub_assign(&mut self, rhs: u64) {
        self.0 = self.0.wrapping_sub(rhs)
    }
}

impl AddAssign<u32> for Address {
    fn add_assign(&mut self, rhs: u32) {
        self.0 = self.0.wrapping_add(rhs as u64)
    }
}

impl SubAssign<u32> for Address {
    fn sub_assign(&mut self, rhs: u32) {
        self.0 = self.0.wrapping_sub(rhs as u64)
    }
}

impl Address {
    pub const MAX: Self = Self(u64::MAX);

    pub const fn zero() -> Self {
        Self(0u64)
    }

    pub fn offset(&self) -> u64 {
        self.0
    }

    pub fn align(&self, alignment: usize) -> Address {
        let offset =
            (*self + alignment.wrapping_sub(1)).offset() & !(alignment as u64).wrapping_sub(1);
        Address(offset)
    }

    pub fn absolute_difference(&self, other: &Address) -> u64 {
        if self >= other {
            self.offset().wrapping_sub(other.offset())
        } else {
            other.offset().wrapping_sub(self.offset())
        }
    }

    pub fn wrap(&self, language: &Language) -> Address {
        language.wrap_offset_in_default_space(self.offset()).into()
    }

    pub fn wrap_and_align(&self, language: &Language) -> Address {
        self.wrap_and_align_with(language, language.address_alignment())
    }

    pub fn wrap_and_align_with(&self, language: &Language, alignment: usize) -> Address {
        self.align(alignment).wrap(language)
    }

    pub fn in_space_bounds(&self, language: &Language) -> bool {
        *self == self.wrap(language)
    }

    pub fn range_in_space_bounds(&self, language: &Language, size: usize) -> bool {
        let upper = *self + size;
        *self <= upper && self.in_space_bounds(language) && upper.in_space_bounds(language)
    }
}

pub trait ToAddress {
    fn to_address(&self, language: &Language) -> Option<Address>;
}

impl ToAddress for Varnode {
    fn to_address(&self, language: &Language) -> Option<Address> {
        if language.in_default_space(self) {
            Some(self.offset().into())
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Encode, Decode)]
pub struct MetaAddressWithContext {
    address: MetaAddress,
    context: ContextSet,
    confidence: Confidence,
}

impl Display for MetaAddressWithContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} (context: {}, confidence: {})",
            self.address, self.context, self.confidence
        )
    }
}

impl<A> From<A> for MetaAddressWithContext
where
    A: Into<MetaAddress>,
{
    fn from(address: A) -> Self {
        Self::new(address.into(), ContextSet::default())
    }
}

impl<A> From<(A, ContextSet)> for MetaAddressWithContext
where
    A: Into<MetaAddress>,
{
    fn from(parts: (A, ContextSet)) -> Self {
        Self::new(parts.0.into(), parts.1)
    }
}

impl<A> From<(A, ContextSet, Confidence)> for MetaAddressWithContext
where
    A: Into<MetaAddress>,
{
    fn from(parts: (A, ContextSet, Confidence)) -> Self {
        Self::new_with(parts.0.into(), parts.1, parts.2)
    }
}

impl MetaAddressWithContext {
    pub fn new(address: impl Into<MetaAddress>, context: ContextSet) -> Self {
        Self::new_with(address.into(), context, Confidence::certain())
    }

    pub fn new_with(
        address: impl Into<MetaAddress>,
        context: ContextSet,
        confidence: Confidence,
    ) -> Self {
        Self {
            address: address.into(),
            context,
            confidence,
        }
    }

    pub fn address(&self) -> MetaAddress {
        self.address
    }

    pub fn context(&self) -> &ContextSet {
        &self.context
    }

    pub fn confidence(&self) -> Confidence {
        self.confidence
    }

    pub fn context_mut(&mut self) -> &mut ContextSet {
        &mut self.context
    }

    pub fn merge_context(&mut self, other: &ContextSet) {
        self.context.merge(other);
    }

    pub fn merge_max_confidence(&mut self, other: Confidence) {
        if other > self.confidence {
            self.confidence = other;
        }
    }

    pub fn into_parts(self) -> (MetaAddress, ContextSet) {
        (self.address, self.context)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct AddressRangeSet(RangeSetBlaze<u64>);

impl FromIterator<Address> for AddressRangeSet {
    fn from_iter<T: IntoIterator<Item = Address>>(iter: T) -> Self {
        Self(iter.into_iter().map(|addr| addr.offset()).collect())
    }
}

impl FromIterator<RangeInclusive<Address>> for AddressRangeSet {
    fn from_iter<T: IntoIterator<Item = RangeInclusive<Address>>>(iter: T) -> Self {
        Self(
            iter.into_iter()
                .map(|r| r.start().offset()..=r.end().offset())
                .collect(),
        )
    }
}

impl FromIterator<MetaAddress> for AddressRangeSet {
    fn from_iter<T: IntoIterator<Item = MetaAddress>>(iter: T) -> Self {
        Self(iter.into_iter().map(|addr| addr.offset()).collect())
    }
}

impl FromIterator<RangeInclusive<MetaAddress>> for AddressRangeSet {
    fn from_iter<T: IntoIterator<Item = RangeInclusive<MetaAddress>>>(iter: T) -> Self {
        Self(
            iter.into_iter()
                .map(|r| r.start().offset()..=r.end().offset())
                .collect(),
        )
    }
}

impl AddressRangeSet {
    pub fn new() -> Self {
        Self(RangeSetBlaze::new())
    }

    pub fn insert(&mut self, address: impl Into<Address>) -> bool {
        self.0.insert(address.into().offset())
    }

    pub fn insert_range(&mut self, range: impl Into<RangeInclusive<Address>>) {
        let range = range.into();
        self.0
            .ranges_insert(range.start().offset()..=range.end().offset());
    }

    pub fn insert_meta_range(&mut self, range: RangeInclusive<MetaAddress>) {
        self.0
            .ranges_insert(range.start().offset()..=range.end().offset());
    }

    pub fn difference(&self, other: &Self) -> Self {
        Self(&self.0 - &other.0)
    }

    pub fn union(&self, other: &Self) -> Self {
        Self(&self.0 | &other.0)
    }

    pub fn intersection(&self, other: &Self) -> Self {
        Self(&self.0 & &other.0)
    }

    pub fn symmetric_difference(&self, other: &Self) -> Self {
        Self(&self.0 ^ &other.0)
    }

    pub fn remove(&mut self, address: impl Into<Address>) {
        self.0.remove(address.into().offset());
    }

    pub fn contains(&self, address: impl Into<Address>) -> bool {
        self.0.contains(address.into().offset())
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = Address> + use<'_> {
        self.0.iter().map(Address::from)
    }

    pub fn ranges(&self) -> impl Iterator<Item = RangeInclusive<Address>> + use<'_> {
        self.0
            .ranges()
            .map(|r| Address::from(*r.start())..=Address::from(*r.end()))
    }

    pub fn clear(&mut self) {
        self.0.clear();
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AddressMap<V>(RangeMapBlaze<u64, V>)
where
    V: Clone + Eq;

impl<V> Default for AddressMap<V>
where
    V: Clone + Eq,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<V> FromIterator<(Address, V)> for AddressMap<V>
where
    V: Clone + Eq,
{
    fn from_iter<T: IntoIterator<Item = (Address, V)>>(iter: T) -> Self {
        let mut map = AddressMap::new();
        for (addr, value) in iter {
            map.insert(addr, value);
        }
        map
    }
}

impl<V> AddressMap<V>
where
    V: Clone + Eq,
{
    pub fn new() -> Self {
        Self(RangeMapBlaze::new())
    }

    pub fn insert(&mut self, address: impl Into<Address>, value: V) -> Option<V> {
        self.0.insert(address.into().offset(), value)
    }

    pub fn remove(&mut self, address: impl Into<Address>) -> Option<V> {
        self.0.remove(address.into().offset())
    }

    pub fn contains_address(&self, address: impl Into<Address>) -> bool {
        self.0.contains_key(address.into().offset())
    }

    pub fn get(&self, address: impl Into<Address>) -> Option<&V> {
        self.0.get(address.into().offset())
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn clear(&mut self) {
        self.0.clear();
    }

    pub fn iter(&self) -> impl Iterator<Item = (Address, &V)> {
        self.0.iter().map(|(k, v)| (Address::from(k), v))
    }

    pub fn range(&self, range: impl RangeBounds<Address>) -> impl Iterator<Item = (Address, V)> {
        let start = range.start_bound().map(|addr| addr.offset());
        let end = range.end_bound().map(|addr| addr.offset());
        self.0
            .range((start, end))
            .map(|(k, v)| (Address::from(k), v))
    }
}

#[derive(
    Copy,
    Clone,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Decode,
    Encode,
    Deserialize,
    Serialize,
)]
pub struct MetaAddress {
    space: AddressSpaceId,
    address: Address,
}

impl Debug for MetaAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{:#x}", self.space, self.address.offset())
    }
}

impl Display for MetaAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{:#x}", self.space, self.address.offset())
    }
}

impl LowerHex for MetaAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:", self.space)?;
        LowerHex::fmt(&self.address, f)
    }
}

impl UpperHex for MetaAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:", self.space)?;
        UpperHex::fmt(&self.address, f)
    }
}

impl From<MetaAddress> for Address {
    fn from(meta: MetaAddress) -> Self {
        meta.address
    }
}

impl From<&MetaAddress> for Address {
    fn from(meta: &MetaAddress) -> Self {
        meta.address
    }
}

impl From<Address> for MetaAddress {
    fn from(address: Address) -> Self {
        Self::in_default_space(address)
    }
}

impl Add<MetaAddress> for MetaAddress {
    type Output = Self;

    fn add(self, rhs: MetaAddress) -> Self {
        assert!(
            self.space == rhs.space,
            "cannot add addresses from different spaces"
        );
        Self::new(self.space, self.address + rhs.address)
    }
}

impl Sub<MetaAddress> for MetaAddress {
    type Output = Self;

    fn sub(self, rhs: MetaAddress) -> Self {
        assert!(
            self.space == rhs.space,
            "cannot subtract addresses from different spaces"
        );
        Self::new(self.space, self.address - rhs.address)
    }
}

impl Add<&'_ MetaAddress> for MetaAddress {
    type Output = Self;

    fn add(self, rhs: &MetaAddress) -> Self {
        assert!(
            self.space == rhs.space,
            "cannot add addresses from different spaces"
        );
        Self::new(self.space, self.address + rhs.address)
    }
}

impl Sub<&'_ MetaAddress> for MetaAddress {
    type Output = Self;

    fn sub(self, rhs: &MetaAddress) -> Self {
        assert!(
            self.space == rhs.space,
            "cannot subtract addresses from different spaces"
        );
        Self::new(self.space, self.address - rhs.address)
    }
}

impl From<i32> for MetaAddress {
    fn from(v: i32) -> Self {
        Self::in_default_space(v as u64)
    }
}

impl From<u64> for MetaAddress {
    fn from(offset: u64) -> Self {
        Self::in_default_space(offset)
    }
}

impl From<u32> for MetaAddress {
    fn from(v: u32) -> Self {
        Self::in_default_space(v as u64)
    }
}

impl From<u16> for MetaAddress {
    fn from(v: u16) -> Self {
        Self::in_default_space(v as u64)
    }
}

impl From<u8> for MetaAddress {
    fn from(v: u8) -> Self {
        Self::in_default_space(v as u64)
    }
}

impl AsRef<Address> for MetaAddress {
    fn as_ref(&self) -> &Address {
        &self.address
    }
}

impl Add<u64> for MetaAddress {
    type Output = Self;

    fn add(self, rhs: u64) -> Self {
        Self {
            space: self.space,
            address: self.address + rhs,
        }
    }
}

impl Sub<u64> for MetaAddress {
    type Output = Self;

    fn sub(self, rhs: u64) -> Self {
        Self {
            space: self.space,
            address: self.address - rhs,
        }
    }
}

impl Add<u32> for MetaAddress {
    type Output = Self;

    fn add(self, rhs: u32) -> Self {
        Self {
            space: self.space,
            address: self.address + rhs,
        }
    }
}

impl Sub<u32> for MetaAddress {
    type Output = Self;

    fn sub(self, rhs: u32) -> Self {
        Self {
            space: self.space,
            address: self.address - rhs,
        }
    }
}

impl Add<usize> for MetaAddress {
    type Output = Self;

    fn add(self, rhs: usize) -> Self {
        Self {
            space: self.space,
            address: self.address + rhs,
        }
    }
}

impl Sub<usize> for MetaAddress {
    type Output = Self;

    fn sub(self, rhs: usize) -> Self {
        Self {
            space: self.space,
            address: self.address - rhs,
        }
    }
}

impl AddAssign<u64> for MetaAddress {
    fn add_assign(&mut self, rhs: u64) {
        self.address += rhs;
    }
}

impl SubAssign<u64> for MetaAddress {
    fn sub_assign(&mut self, rhs: u64) {
        self.address -= rhs;
    }
}

impl AddAssign<u32> for MetaAddress {
    fn add_assign(&mut self, rhs: u32) {
        self.address += rhs;
    }
}

impl SubAssign<u32> for MetaAddress {
    fn sub_assign(&mut self, rhs: u32) {
        self.address -= rhs;
    }
}

impl AddAssign<usize> for MetaAddress {
    fn add_assign(&mut self, rhs: usize) {
        self.address += rhs;
    }
}

impl SubAssign<usize> for MetaAddress {
    fn sub_assign(&mut self, rhs: usize) {
        self.address -= rhs;
    }
}

impl From<MetaAddress> for u64 {
    fn from(meta: MetaAddress) -> Self {
        meta.address.offset()
    }
}

impl From<&MetaAddress> for u64 {
    fn from(meta: &MetaAddress) -> Self {
        meta.address.offset()
    }
}

impl From<MetaAddress> for u32 {
    fn from(meta: MetaAddress) -> Self {
        meta.address.offset() as u32
    }
}

impl From<&MetaAddress> for u32 {
    fn from(meta: &MetaAddress) -> Self {
        meta.address.offset() as u32
    }
}

impl From<MetaAddress> for usize {
    fn from(meta: MetaAddress) -> Self {
        meta.address.offset() as usize
    }
}

impl From<&MetaAddress> for usize {
    fn from(meta: &MetaAddress) -> Self {
        meta.address.offset() as usize
    }
}

impl MetaAddress {
    pub fn new(space: AddressSpaceId, address: impl Into<Address>) -> Self {
        Self {
            space,
            address: address.into(),
        }
    }

    pub const fn zero(space: AddressSpaceId) -> Self {
        Self {
            space,
            address: Address::zero(),
        }
    }

    pub fn in_default_space(address: impl Into<Address>) -> Self {
        Self {
            space: AddressSpaceId::default(),
            address: address.into(),
        }
    }

    pub fn address(&self) -> Address {
        self.address
    }

    pub fn space(&self) -> AddressSpaceId {
        self.space
    }

    pub fn offset(&self) -> u64 {
        self.address.offset()
    }

    pub fn wrap(&self, language: &Language) -> Self {
        Self {
            space: self.space,
            address: self.address.wrap(language),
        }
    }

    pub fn align(&self, alignment: usize) -> Self {
        Self {
            space: self.space,
            address: self.address.align(alignment),
        }
    }

    pub fn in_space_bounds(&self, language: &Language) -> bool {
        self.address.in_space_bounds(language)
    }

    pub fn range_in_space_bounds(&self, language: &Language, size: usize) -> bool {
        self.address.range_in_space_bounds(language, size)
    }
}
