use std::collections::BTreeMap;
use std::fmt::{Debug, Display, LowerHex, UpperHex};
use std::num::ParseIntError;
use std::ops::{Add, AddAssign, Bound, Range, RangeBounds, RangeInclusive, Sub, SubAssign};
use std::str::FromStr;
use std::{fmt, iter, mem};

use rangemap::{RangeInclusiveMap, RangeInclusiveSet};
use serde::{Deserialize, Serialize};

use crate::lifter::{ContextSet, Language, Varnode};
use crate::storage::entities::schema::{ENTITY_KEY_ADDRESS_ID, ENTITY_KEY_RAW_ADDRESS_ID};
use crate::storage::entities::{EntityKey, EntityKeyCodec, EntityKeyId};
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
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
    Deserialize,
    Serialize,
)]
#[rkyv(derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash))]
#[repr(transparent)]
pub struct RawAddress(u64);

impl EntityKeyCodec for RawAddress {
    fn decode(input: &mut &[u8]) -> Option<Self> {
        let (value, rest) = input.split_at_checked(mem::size_of::<u64>())?;
        *input = rest;
        Some(Self::from(u64::from_be_bytes(value.try_into().ok()?)))
    }

    fn encode(&self, output: &mut impl Extend<u8>) {
        output.extend(self.offset().to_be_bytes())
    }
}

impl EntityKey for RawAddress {
    const ID: EntityKeyId = ENTITY_KEY_RAW_ADDRESS_ID;
}

impl Debug for RawAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl Display for RawAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl FromStr for RawAddress {
    type Err = ParseIntError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let address = value
            .strip_prefix("0x")
            .or_else(|| value.strip_prefix("0X"))
            .map_or_else(|| value.parse::<u64>(), |hex| u64::from_str_radix(hex, 16))?;

        Ok(Self(address))
    }
}

impl LowerHex for RawAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        LowerHex::fmt(&self.0, f)
    }
}

impl UpperHex for RawAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        UpperHex::fmt(&self.0, f)
    }
}

impl AsRef<RawAddress> for RawAddress {
    fn as_ref(&self) -> &RawAddress {
        self
    }
}

impl AsRef<u64> for RawAddress {
    fn as_ref(&self) -> &u64 {
        &self.0
    }
}

impl PartialEq<u8> for RawAddress {
    fn eq(&self, other: &u8) -> bool {
        self.0 == *other as u64
    }
}

impl PartialEq<u16> for RawAddress {
    fn eq(&self, other: &u16) -> bool {
        self.0 == *other as u64
    }
}

impl PartialEq<u32> for RawAddress {
    fn eq(&self, other: &u32) -> bool {
        self.0 == *other as u64
    }
}

impl PartialEq<u64> for RawAddress {
    fn eq(&self, other: &u64) -> bool {
        self.0 == *other
    }
}

impl PartialEq<RawAddress> for u8 {
    fn eq(&self, other: &RawAddress) -> bool {
        *self as u64 == other.0
    }
}

impl PartialEq<RawAddress> for u16 {
    fn eq(&self, other: &RawAddress) -> bool {
        *self as u64 == other.0
    }
}

impl PartialEq<RawAddress> for u32 {
    fn eq(&self, other: &RawAddress) -> bool {
        *self as u64 == other.0
    }
}

impl PartialEq<RawAddress> for u64 {
    fn eq(&self, other: &RawAddress) -> bool {
        *self == other.0
    }
}

impl PartialEq<RawAddress> for usize {
    fn eq(&self, other: &RawAddress) -> bool {
        *self as u64 == other.0
    }
}

impl From<usize> for RawAddress {
    fn from(v: usize) -> Self {
        Self(v as u64)
    }
}

impl From<i32> for RawAddress {
    fn from(v: i32) -> Self {
        Self(v as u64)
    }
}

impl From<u64> for RawAddress {
    fn from(v: u64) -> Self {
        Self(v)
    }
}

impl From<u32> for RawAddress {
    fn from(v: u32) -> Self {
        Self(v as u64)
    }
}

impl From<u16> for RawAddress {
    fn from(v: u16) -> Self {
        Self(v as u64)
    }
}

impl From<u8> for RawAddress {
    fn from(v: u8) -> Self {
        Self(v as u64)
    }
}

impl From<RawAddress> for usize {
    fn from(t: RawAddress) -> Self {
        t.0 as _
    }
}

impl From<&'_ RawAddress> for usize {
    fn from(t: &'_ RawAddress) -> Self {
        t.0 as _
    }
}

impl From<RawAddress> for u64 {
    fn from(t: RawAddress) -> Self {
        t.0 as _
    }
}

impl From<&'_ RawAddress> for u64 {
    fn from(t: &'_ RawAddress) -> Self {
        t.0 as _
    }
}

impl From<RawAddress> for u32 {
    fn from(t: RawAddress) -> Self {
        t.0 as _
    }
}

impl From<&'_ RawAddress> for u32 {
    fn from(t: &'_ RawAddress) -> Self {
        t.0 as _
    }
}

impl From<RawAddress> for u16 {
    fn from(t: RawAddress) -> Self {
        t.0 as _
    }
}

impl From<&'_ RawAddress> for u16 {
    fn from(t: &'_ RawAddress) -> Self {
        t.0 as _
    }
}

impl From<RawAddress> for u8 {
    fn from(t: RawAddress) -> Self {
        t.0 as _
    }
}

impl From<&'_ RawAddress> for u8 {
    fn from(t: &'_ RawAddress) -> Self {
        t.0 as _
    }
}

impl Add<RawAddress> for RawAddress {
    type Output = Self;

    fn add(self, rhs: RawAddress) -> Self {
        Self(self.0.wrapping_add(rhs.0))
    }
}

impl Sub<RawAddress> for RawAddress {
    type Output = Self;

    fn sub(self, rhs: RawAddress) -> Self {
        Self(self.0.wrapping_sub(rhs.0))
    }
}

impl Add<&'_ RawAddress> for RawAddress {
    type Output = Self;

    fn add(self, rhs: &RawAddress) -> Self {
        Self(self.0.wrapping_add(rhs.0))
    }
}

impl Sub<&'_ RawAddress> for RawAddress {
    type Output = Self;

    fn sub(self, rhs: &RawAddress) -> Self {
        Self(self.0.wrapping_sub(rhs.0))
    }
}

impl Add<usize> for RawAddress {
    type Output = Self;

    fn add(self, rhs: usize) -> Self {
        Self(self.0.wrapping_add(rhs as u64))
    }
}

impl Sub<usize> for RawAddress {
    type Output = Self;

    fn sub(self, rhs: usize) -> Self {
        Self(self.0.wrapping_sub(rhs as u64))
    }
}

impl Add<u64> for RawAddress {
    type Output = Self;

    fn add(self, rhs: u64) -> Self {
        Self(self.0.wrapping_add(rhs))
    }
}

impl Sub<u64> for RawAddress {
    type Output = Self;

    fn sub(self, rhs: u64) -> Self {
        Self(self.0.wrapping_sub(rhs))
    }
}

impl Add<u32> for RawAddress {
    type Output = Self;

    fn add(self, rhs: u32) -> Self {
        Self(self.0.wrapping_add(rhs as u64))
    }
}

impl Sub<u32> for RawAddress {
    type Output = Self;

    fn sub(self, rhs: u32) -> Self {
        Self(self.0.wrapping_sub(rhs as u64))
    }
}

impl AddAssign<RawAddress> for RawAddress {
    fn add_assign(&mut self, rhs: RawAddress) {
        self.0 = self.0.wrapping_add(rhs.0)
    }
}

impl SubAssign<RawAddress> for RawAddress {
    fn sub_assign(&mut self, rhs: RawAddress) {
        self.0 = self.0.wrapping_sub(rhs.0)
    }
}

impl AddAssign<&'_ RawAddress> for RawAddress {
    fn add_assign(&mut self, rhs: &'_ RawAddress) {
        self.0 = self.0.wrapping_add(rhs.0)
    }
}

impl SubAssign<&'_ RawAddress> for RawAddress {
    fn sub_assign(&mut self, rhs: &'_ RawAddress) {
        self.0 = self.0.wrapping_sub(rhs.0)
    }
}

impl AddAssign<usize> for RawAddress {
    fn add_assign(&mut self, rhs: usize) {
        self.0 = self.0.wrapping_add(rhs as u64)
    }
}

impl SubAssign<usize> for RawAddress {
    fn sub_assign(&mut self, rhs: usize) {
        self.0 = self.0.wrapping_sub(rhs as u64)
    }
}

impl AddAssign<u64> for RawAddress {
    fn add_assign(&mut self, rhs: u64) {
        self.0 = self.0.wrapping_add(rhs)
    }
}

impl SubAssign<u64> for RawAddress {
    fn sub_assign(&mut self, rhs: u64) {
        self.0 = self.0.wrapping_sub(rhs)
    }
}

impl AddAssign<u32> for RawAddress {
    fn add_assign(&mut self, rhs: u32) {
        self.0 = self.0.wrapping_add(rhs as u64)
    }
}

impl SubAssign<u32> for RawAddress {
    fn sub_assign(&mut self, rhs: u32) {
        self.0 = self.0.wrapping_sub(rhs as u64)
    }
}

impl RawAddress {
    pub const MAX: Self = Self(u64::MAX);

    pub const fn zero() -> Self {
        Self(0u64)
    }

    pub fn new(addr: impl Into<Self>) -> Self {
        addr.into()
    }

    pub fn offset(&self) -> u64 {
        self.0
    }

    pub fn checked_offset_from(&self, base: RawAddress) -> Option<u64> {
        self.0.checked_sub(base.0)
    }

    pub fn align_down(&self, alignment: usize) -> RawAddress {
        RawAddress(self.0 & !(alignment as u64).wrapping_sub(1))
    }

    pub fn checked_add(&self, offset: impl Into<RawAddress>) -> Option<Self> {
        let offset = offset.into();
        self.0.checked_add(offset.0).map(Self)
    }

    pub fn checked_sub(&self, offset: impl Into<RawAddress>) -> Option<Self> {
        let offset = offset.into();
        self.0.checked_sub(offset.0).map(Self)
    }

    pub fn align(&self, alignment: usize) -> RawAddress {
        let offset =
            (*self + alignment.wrapping_sub(1)).offset() & !(alignment as u64).wrapping_sub(1);
        RawAddress(offset)
    }

    pub fn absolute_difference(&self, other: &RawAddress) -> u64 {
        if self >= other {
            self.offset().wrapping_sub(other.offset())
        } else {
            other.offset().wrapping_sub(self.offset())
        }
    }

    pub fn wrap(&self, language: &Language) -> RawAddress {
        language.wrap_offset_in_default_space(self.offset()).into()
    }

    pub fn wrap_and_align(&self, language: &Language) -> RawAddress {
        self.wrap_and_align_with(language, language.address_alignment())
    }

    pub fn wrap_and_align_with(&self, language: &Language, alignment: usize) -> RawAddress {
        self.wrap(language).align(alignment)
    }

    pub fn in_space_bounds(&self, language: &Language) -> bool {
        *self == self.wrap(language)
    }

    pub fn range_in_space_bounds(&self, language: &Language, size: usize) -> bool {
        let upper = *self + size;
        *self <= upper && self.in_space_bounds(language) && upper.in_space_bounds(language)
    }
}

pub trait ToRawAddress {
    fn to_address(&self, language: &Language) -> Option<RawAddress>;
}

impl ToRawAddress for Varnode {
    fn to_address(&self, language: &Language) -> Option<RawAddress> {
        if language.in_default_space(self) {
            Some(self.offset().into())
        } else {
            None
        }
    }
}

#[derive(
    Debug,
    Clone,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
pub struct AddressWithContext {
    address: Address,
    context: ContextSet,
    confidence: Confidence,
}

impl Display for AddressWithContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} (context: {}, confidence: {})",
            self.address, self.context, self.confidence
        )
    }
}

impl<A> From<A> for AddressWithContext
where
    A: Into<Address>,
{
    fn from(address: A) -> Self {
        Self::new(address.into(), ContextSet::default())
    }
}

impl<A> From<(A, ContextSet)> for AddressWithContext
where
    A: Into<Address>,
{
    fn from(parts: (A, ContextSet)) -> Self {
        Self::new(parts.0.into(), parts.1)
    }
}

impl<A> From<(A, ContextSet, Confidence)> for AddressWithContext
where
    A: Into<Address>,
{
    fn from(parts: (A, ContextSet, Confidence)) -> Self {
        Self::new_with(parts.0.into(), parts.1, parts.2)
    }
}

impl AddressWithContext {
    pub fn new(address: impl Into<Address>, context: ContextSet) -> Self {
        Self::new_with(address.into(), context, Confidence::certain())
    }

    pub fn new_with(
        address: impl Into<Address>,
        context: ContextSet,
        confidence: Confidence,
    ) -> Self {
        Self {
            address: address.into(),
            context,
            confidence,
        }
    }

    pub fn address(&self) -> Address {
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

    pub fn into_parts(self) -> (Address, ContextSet) {
        (self.address, self.context)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct RawAddressRangeSet(RangeInclusiveSet<u64>);

impl FromIterator<RawAddress> for RawAddressRangeSet {
    fn from_iter<T: IntoIterator<Item = RawAddress>>(iter: T) -> Self {
        Self(
            iter.into_iter()
                .map(|address| address.offset()..=address.offset())
                .collect(),
        )
    }
}

impl FromIterator<RangeInclusive<RawAddress>> for RawAddressRangeSet {
    fn from_iter<T: IntoIterator<Item = RangeInclusive<RawAddress>>>(iter: T) -> Self {
        Self(
            iter.into_iter()
                .map(|r| r.start().offset()..=r.end().offset())
                .collect(),
        )
    }
}

impl FromIterator<Address> for RawAddressRangeSet {
    fn from_iter<T: IntoIterator<Item = Address>>(iter: T) -> Self {
        Self(
            iter.into_iter()
                .map(|address| address.offset()..=address.offset())
                .collect(),
        )
    }
}

impl FromIterator<RangeInclusive<Address>> for RawAddressRangeSet {
    fn from_iter<T: IntoIterator<Item = RangeInclusive<Address>>>(iter: T) -> Self {
        Self(
            iter.into_iter()
                .map(|r| r.start().offset()..=r.end().offset())
                .collect(),
        )
    }
}

impl RawAddressRangeSet {
    pub fn new() -> Self {
        Self(RangeInclusiveSet::new())
    }

    pub fn union(&self, other: &Self) -> Self {
        Self(&self.0 | &other.0)
    }

    pub fn intersection(&self, other: &Self) -> Self {
        Self(&self.0 & &other.0)
    }

    pub fn contains(&self, address: impl Into<RawAddress>) -> bool {
        self.0.contains(&address.into().offset())
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = RawAddress> + use<'_> {
        self.0
            .iter()
            .flat_map(|range| range.clone())
            .map(RawAddress::from)
    }

    pub fn ranges(&self) -> impl Iterator<Item = RangeInclusive<RawAddress>> + use<'_> {
        self.0
            .iter()
            .map(|r| RawAddress::from(*r.start())..=RawAddress::from(*r.end()))
    }

    pub fn overlapping_ranges(
        &self,
        range: RangeInclusive<RawAddress>,
    ) -> impl Iterator<Item = RangeInclusive<RawAddress>> + use<'_> {
        let start = range.start().offset();
        let end = range.end().offset();
        (start <= end)
            .then_some(start..=end)
            .into_iter()
            .flat_map(move |range| {
                self.0
                    .overlapping(range)
                    .map(|range| RawAddress::from(*range.start())..=RawAddress::from(*range.end()))
            })
    }

    pub fn range_count(&self) -> usize {
        self.0.len()
    }

    pub fn span(&self) -> Option<RangeInclusive<RawAddress>> {
        Some(RawAddress::from(*self.0.first()?.start())..=RawAddress::from(*self.0.last()?.end()))
    }

    pub fn insert(&mut self, address: impl Into<RawAddress>) -> bool {
        let address = address.into().offset();
        let inserted = !self.0.contains(&address);
        self.0.insert(address..=address);
        inserted
    }

    pub fn insert_range(&mut self, range: impl Into<RangeInclusive<RawAddress>>) {
        let range = range.into();
        self.0.insert(range.start().offset()..=range.end().offset());
    }

    pub fn intersects_range(&self, range: impl Into<RangeInclusive<RawAddress>>) -> bool {
        let range = range.into();
        let start = range.start().offset();
        let end = range.end().offset();

        start <= end && self.0.overlaps(&(start..=end))
    }

    pub fn insert_meta_range(&mut self, range: RangeInclusive<Address>) {
        self.0.insert(range.start().offset()..=range.end().offset());
    }

    pub fn difference(&self, other: &Self) -> Self {
        let mut difference = RangeInclusiveSet::new();
        for range in self.ranges() {
            let excluded = other.overlapping_ranges(range.clone());
            for range in range.difference(excluded) {
                difference.insert(range.start().offset()..=range.end().offset());
            }
        }
        Self(difference)
    }

    pub fn symmetric_difference(&self, other: &Self) -> Self {
        self.difference(other).union(&other.difference(self))
    }

    pub fn remove(&mut self, address: impl Into<RawAddress>) {
        let address = address.into().offset();
        self.0.remove(address..=address);
    }

    pub fn remove_range(&mut self, range: impl Into<RangeInclusive<RawAddress>>) {
        let range = range.into();
        self.0.remove(range.start().offset()..=range.end().offset());
    }

    pub fn clear(&mut self) {
        self.0.clear();
    }
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
pub struct AddressRange {
    space: AddressSpaceId,
    start: RawAddress,
    end: RawAddress,
}

impl AddressRange {
    pub fn new(space: AddressSpaceId, start: RawAddress, end: RawAddress) -> Self {
        Self { space, start, end }
    }

    pub fn from_size(start: Address, size: u64) -> Option<Self> {
        let end = size
            .checked_sub(1)
            .and_then(|last| start.raw_address().checked_add(last))?;
        Some(Self::new(start.space(), start.raw_address(), end))
    }

    pub fn point(address: Address) -> Self {
        Self::new(
            address.space(),
            address.raw_address(),
            address.raw_address(),
        )
    }

    pub fn space(&self) -> AddressSpaceId {
        self.space
    }

    pub fn start(&self) -> RawAddress {
        self.start
    }

    pub fn end(&self) -> RawAddress {
        self.end
    }

    pub fn size(&self) -> u64 {
        self.end
            .offset()
            .saturating_sub(self.start.offset())
            .saturating_add(1)
    }

    pub fn is_empty(&self) -> bool {
        self.end < self.start
    }

    pub fn contains(&self, address: RawAddress) -> bool {
        self.start <= address && address <= self.end
    }

    pub fn contains_address(&self, address: Address) -> bool {
        self.space == address.space() && self.contains(address.raw_address())
    }

    pub fn remaining_from(&self, address: Address) -> Option<u64> {
        if !self.contains_address(address) {
            return None;
        }
        self.end
            .offset()
            .checked_sub(address.offset())?
            .checked_add(1)
    }

    pub fn start_address(&self) -> Address {
        Address::new(self.space, self.start)
    }

    pub fn end_address(&self) -> Address {
        Address::new(self.space, self.end)
    }

    pub fn intersects(&self, other: &AddressRange) -> bool {
        self.space == other.space && self.start <= other.end && other.start <= self.end
    }

    pub fn raw_range(&self) -> RangeInclusive<RawAddress> {
        self.start..=self.end
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct AddressRangeSet {
    spaces: BTreeMap<AddressSpaceId, RawAddressRangeSet>,
}

impl AddressRangeSet {
    pub fn new() -> Self {
        Self {
            spaces: BTreeMap::new(),
        }
    }

    pub fn contains(&self, address: impl Into<Address>) -> bool {
        let address = address.into();
        self.spaces
            .get(&address.space())
            .is_some_and(|ranges| ranges.contains(address.raw_address()))
    }

    pub fn spaces(&self) -> impl Iterator<Item = (AddressSpaceId, &RawAddressRangeSet)> + '_ {
        self.spaces.iter().map(|(space, ranges)| (*space, ranges))
    }

    pub fn ranges(&self) -> impl Iterator<Item = AddressRange> + '_ {
        self.spaces.iter().flat_map(|(space, ranges)| {
            ranges
                .ranges()
                .map(move |range| AddressRange::new(*space, *range.start(), *range.end()))
        })
    }

    pub fn intersects_range(&self, range: &AddressRange) -> bool {
        self.spaces
            .get(&range.space())
            .is_some_and(|ranges| ranges.intersects_range(range.raw_range()))
    }

    pub fn range_count(&self) -> usize {
        self.spaces
            .values()
            .map(RawAddressRangeSet::range_count)
            .sum()
    }

    pub fn addresses(&self) -> impl Iterator<Item = Address> + '_ {
        self.spaces.iter().flat_map(|(space, ranges)| {
            ranges
                .iter()
                .map(move |address| Address::new(*space, address))
        })
    }

    pub fn is_empty(&self) -> bool {
        self.spaces.values().all(RawAddressRangeSet::is_empty)
    }

    pub fn insert(&mut self, address: Address) -> bool {
        self.spaces
            .entry(address.space())
            .or_default()
            .insert(address.raw_address())
    }

    pub fn insert_range(&mut self, range: AddressRange) {
        if range.is_empty() {
            return;
        }

        self.spaces
            .entry(range.space())
            .or_default()
            .insert_range(range.raw_range());
    }

    pub fn insert_raw_range(
        &mut self,
        space: AddressSpaceId,
        range: impl Into<RangeInclusive<RawAddress>>,
    ) {
        self.spaces.entry(space).or_default().insert_range(range);
    }

    pub fn insert_meta_range(&mut self, range: RangeInclusive<Address>) {
        let space = range.start().space();
        self.spaces
            .entry(space)
            .or_default()
            .insert_meta_range(range);
    }

    pub fn remove_range(&mut self, range: AddressRange) {
        let Some(ranges) = self.spaces.get_mut(&range.space()) else {
            return;
        };
        ranges.remove_range(range.raw_range());
        if ranges.is_empty() {
            self.spaces.remove(&range.space());
        }
    }

    pub fn difference(&self, other: &Self) -> Self {
        let mut difference = self.clone();

        for (space, ranges) in &other.spaces {
            if let Some(existing) = difference.spaces.get_mut(space) {
                *existing = existing.difference(ranges);
            }
        }

        difference.spaces.retain(|_, ranges| !ranges.is_empty());
        difference
    }

    pub fn union(&self, other: &Self) -> Self {
        let mut union = self.clone();

        for (space, ranges) in &other.spaces {
            let merged = union.spaces.entry(*space).or_default().union(ranges);
            union.spaces.insert(*space, merged);
        }

        union
    }

    pub fn intersection(&self, other: &Self) -> Self {
        let mut intersection = Self::new();

        for (space, ranges) in &self.spaces {
            let Some(other_ranges) = other.spaces.get(space) else {
                continue;
            };
            let ranges = ranges.intersection(other_ranges);
            if !ranges.is_empty() {
                intersection.spaces.insert(*space, ranges);
            }
        }

        intersection
    }

    pub fn intersects(&self, other: &Self) -> bool {
        other.ranges().any(|range| self.intersects_range(&range))
    }

    pub fn spanning_ranges(&self) -> Self {
        let mut spanning = Self::new();

        for (space, ranges) in &self.spaces {
            if let Some(span) = ranges.span() {
                spanning.insert_raw_range(*space, span);
            }
        }

        spanning
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RawAddressMap<V>(RangeInclusiveMap<u64, V>)
where
    V: Clone + Eq;

impl<V> Default for RawAddressMap<V>
where
    V: Clone + Eq,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<V> FromIterator<(RawAddress, V)> for RawAddressMap<V>
where
    V: Clone + Eq,
{
    fn from_iter<T: IntoIterator<Item = (RawAddress, V)>>(iter: T) -> Self {
        let mut map = RawAddressMap::new();
        for (addr, value) in iter {
            map.insert(addr, value);
        }
        map
    }
}

impl<V> RawAddressMap<V>
where
    V: Clone + Eq,
{
    pub fn new() -> Self {
        Self(RangeInclusiveMap::new())
    }

    pub fn contains_address(&self, address: impl Into<RawAddress>) -> bool {
        self.0.contains_key(&address.into().offset())
    }

    pub fn get(&self, address: impl Into<RawAddress>) -> Option<&V> {
        self.0.get(&address.into().offset())
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (RawAddress, &V)> {
        self.0.iter().flat_map(|(range, value)| {
            range
                .clone()
                .map(move |address| (RawAddress::from(address), value))
        })
    }

    pub fn run_count(&self) -> usize {
        self.0.len()
    }

    pub fn range(
        &self,
        range: impl RangeBounds<RawAddress>,
    ) -> impl Iterator<Item = (RawAddress, V)> {
        let range = raw_address_bounds(&range);
        range.into_iter().flat_map(move |query| {
            self.0
                .overlapping(query.clone())
                .flat_map(move |(stored, value)| {
                    let start = (*stored.start()).max(*query.start());
                    let end = (*stored.end()).min(*query.end());
                    (start..=end).map(move |address| (RawAddress::from(address), value.clone()))
                })
        })
    }

    pub fn insert(&mut self, address: impl Into<RawAddress>, value: V) -> Option<V> {
        let address = address.into().offset();
        let previous = self.0.get(&address).cloned();
        self.0.insert(address..=address, value);
        previous
    }

    pub fn insert_range(&mut self, range: impl Into<RangeInclusive<RawAddress>>, value: V) {
        let range = range.into();
        self.0
            .insert(range.start().offset()..=range.end().offset(), value);
    }

    pub fn remove(&mut self, address: impl Into<RawAddress>) -> Option<V> {
        let address = address.into().offset();
        let previous = self.0.get(&address).cloned();
        self.0.remove(address..=address);
        previous
    }

    pub fn clear(&mut self) {
        self.0.clear();
    }
}

impl<V> RawAddressMap<V>
where
    V: Clone + Ord,
{
    pub fn max_in_range(&self, range: impl Into<RangeInclusive<RawAddress>>) -> Option<V> {
        let range = range.into();
        let start = range.start().offset();
        let end = range.end().offset();
        (start <= end)
            .then(|| {
                self.0
                    .overlapping(start..=end)
                    .map(|(_, value)| value.clone())
                    .max()
            })
            .flatten()
    }
}

fn raw_address_bounds(range: &impl RangeBounds<RawAddress>) -> Option<RangeInclusive<u64>> {
    let start = match range.start_bound() {
        Bound::Included(address) => address.offset(),
        Bound::Excluded(address) => address.offset().checked_add(1)?,
        Bound::Unbounded => u64::MIN,
    };
    let end = match range.end_bound() {
        Bound::Included(address) => address.offset(),
        Bound::Excluded(address) => address.offset().checked_sub(1)?,
        Bound::Unbounded => u64::MAX,
    };
    (start <= end).then_some(start..=end)
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
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
    Deserialize,
    Serialize,
)]
#[rkyv(derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash))]
pub struct Address {
    space: AddressSpaceId,
    address: RawAddress,
}

impl EntityKeyCodec for Address {
    fn decode(input: &mut &[u8]) -> Option<Self> {
        let space = AddressSpaceId::decode(input)?;
        let address = RawAddress::decode(input)?;
        Some(Self { space, address })
    }

    fn encode(&self, output: &mut impl Extend<u8>) {
        self.space.encode(output);
        self.address.encode(output);
    }
}

impl EntityKey for Address {
    const ID: EntityKeyId = ENTITY_KEY_ADDRESS_ID;
}

impl Debug for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{:#x}", self.space, self.address.offset())
    }
}

impl Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{:#x}", self.space, self.address.offset())
    }
}

impl LowerHex for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:", self.space)?;
        LowerHex::fmt(&self.address, f)
    }
}

impl UpperHex for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:", self.space)?;
        UpperHex::fmt(&self.address, f)
    }
}

impl From<Address> for RawAddress {
    fn from(meta: Address) -> Self {
        meta.address
    }
}

impl From<&Address> for RawAddress {
    fn from(meta: &Address) -> Self {
        meta.address
    }
}

impl From<RawAddress> for Address {
    fn from(address: RawAddress) -> Self {
        Self::in_default_space(address)
    }
}

impl Add<Address> for Address {
    type Output = Self;

    fn add(self, rhs: Address) -> Self {
        assert!(
            self.space == rhs.space,
            "cannot add addresses from different spaces"
        );
        Self::new(self.space, self.address + rhs.address)
    }
}

impl Sub<Address> for Address {
    type Output = Self;

    fn sub(self, rhs: Address) -> Self {
        assert!(
            self.space == rhs.space,
            "cannot subtract addresses from different spaces"
        );
        Self::new(self.space, self.address - rhs.address)
    }
}

impl Add<&'_ Address> for Address {
    type Output = Self;

    fn add(self, rhs: &Address) -> Self {
        assert!(
            self.space == rhs.space,
            "cannot add addresses from different spaces"
        );
        Self::new(self.space, self.address + rhs.address)
    }
}

impl Sub<&'_ Address> for Address {
    type Output = Self;

    fn sub(self, rhs: &Address) -> Self {
        assert!(
            self.space == rhs.space,
            "cannot subtract addresses from different spaces"
        );
        Self::new(self.space, self.address - rhs.address)
    }
}

impl From<i32> for Address {
    fn from(v: i32) -> Self {
        Self::in_default_space(v as u64)
    }
}

impl From<u64> for Address {
    fn from(offset: u64) -> Self {
        Self::in_default_space(offset)
    }
}

impl From<u32> for Address {
    fn from(v: u32) -> Self {
        Self::in_default_space(v as u64)
    }
}

impl From<u16> for Address {
    fn from(v: u16) -> Self {
        Self::in_default_space(v as u64)
    }
}

impl From<u8> for Address {
    fn from(v: u8) -> Self {
        Self::in_default_space(v as u64)
    }
}

impl AsRef<RawAddress> for Address {
    fn as_ref(&self) -> &RawAddress {
        &self.address
    }
}

impl Add<u64> for Address {
    type Output = Self;

    fn add(self, rhs: u64) -> Self {
        Self {
            space: self.space,
            address: self.address + rhs,
        }
    }
}

impl Sub<u64> for Address {
    type Output = Self;

    fn sub(self, rhs: u64) -> Self {
        Self {
            space: self.space,
            address: self.address - rhs,
        }
    }
}

impl Add<u32> for Address {
    type Output = Self;

    fn add(self, rhs: u32) -> Self {
        Self {
            space: self.space,
            address: self.address + rhs,
        }
    }
}

impl Sub<u32> for Address {
    type Output = Self;

    fn sub(self, rhs: u32) -> Self {
        Self {
            space: self.space,
            address: self.address - rhs,
        }
    }
}

impl Add<usize> for Address {
    type Output = Self;

    fn add(self, rhs: usize) -> Self {
        Self {
            space: self.space,
            address: self.address + rhs,
        }
    }
}

impl Sub<usize> for Address {
    type Output = Self;

    fn sub(self, rhs: usize) -> Self {
        Self {
            space: self.space,
            address: self.address - rhs,
        }
    }
}

impl AddAssign<u64> for Address {
    fn add_assign(&mut self, rhs: u64) {
        self.address += rhs;
    }
}

impl SubAssign<u64> for Address {
    fn sub_assign(&mut self, rhs: u64) {
        self.address -= rhs;
    }
}

impl AddAssign<u32> for Address {
    fn add_assign(&mut self, rhs: u32) {
        self.address += rhs;
    }
}

impl SubAssign<u32> for Address {
    fn sub_assign(&mut self, rhs: u32) {
        self.address -= rhs;
    }
}

impl AddAssign<usize> for Address {
    fn add_assign(&mut self, rhs: usize) {
        self.address += rhs;
    }
}

impl SubAssign<usize> for Address {
    fn sub_assign(&mut self, rhs: usize) {
        self.address -= rhs;
    }
}

impl From<Address> for u64 {
    fn from(meta: Address) -> Self {
        meta.address.offset()
    }
}

impl From<&Address> for u64 {
    fn from(meta: &Address) -> Self {
        meta.address.offset()
    }
}

impl From<Address> for u32 {
    fn from(meta: Address) -> Self {
        meta.address.offset() as u32
    }
}

impl From<&Address> for u32 {
    fn from(meta: &Address) -> Self {
        meta.address.offset() as u32
    }
}

impl From<Address> for usize {
    fn from(meta: Address) -> Self {
        meta.address.offset() as usize
    }
}

impl From<&Address> for usize {
    fn from(meta: &Address) -> Self {
        meta.address.offset() as usize
    }
}

impl Address {
    pub const MINIMUM: Self = Self::zero(AddressSpaceId::new(0));

    pub fn new(space: AddressSpaceId, address: impl Into<RawAddress>) -> Self {
        Self {
            space,
            address: address.into(),
        }
    }

    pub const fn zero(space: AddressSpaceId) -> Self {
        Self {
            space,
            address: RawAddress::zero(),
        }
    }

    pub fn in_default_space(address: impl Into<RawAddress>) -> Self {
        Self {
            space: AddressSpaceId::default(),
            address: address.into(),
        }
    }

    pub fn in_space(
        address: impl Into<RawAddress>,
        space: impl Into<Option<AddressSpaceId>>,
    ) -> Self {
        match space.into() {
            Some(space_id) => Self::new(space_id, address),
            None => Self::in_default_space(address),
        }
    }

    pub fn raw_address(&self) -> RawAddress {
        self.address
    }

    pub fn space(&self) -> AddressSpaceId {
        self.space
    }

    pub fn offset(&self) -> u64 {
        self.address.offset()
    }

    pub fn in_space_bounds(&self, language: &Language) -> bool {
        self.address.in_space_bounds(language)
    }

    pub fn range_in_space_bounds(&self, language: &Language, size: usize) -> bool {
        self.address.range_in_space_bounds(language, size)
    }

    pub(crate) fn bounds_in_space<R>(space: AddressSpaceId, range: &R) -> (Bound<Self>, Bound<Self>)
    where
        R: RangeBounds<RawAddress> + ?Sized,
    {
        let start = match range.start_bound() {
            Bound::Included(address) => Bound::Included(Self::new(space, *address)),
            Bound::Excluded(address) => Bound::Excluded(Self::new(space, *address)),
            Bound::Unbounded => Bound::Included(Self::zero(space)),
        };
        let end = match range.end_bound() {
            Bound::Included(address) => Bound::Included(Self::new(space, *address)),
            Bound::Excluded(address) => Bound::Excluded(Self::new(space, *address)),
            Bound::Unbounded => Bound::Included(Self::new(space, RawAddress::MAX)),
        };
        (start, end)
    }

    pub fn checked_add(&self, offset: impl Into<RawAddress>) -> Option<Self> {
        let offset = offset.into();
        self.raw_address()
            .checked_add(offset)
            .map(|new_address| Self {
                space: self.space,
                address: new_address,
            })
    }

    pub fn checked_sub(&self, offset: impl Into<RawAddress>) -> Option<Self> {
        let offset = offset.into();
        self.raw_address()
            .checked_sub(offset)
            .map(|new_address| Self {
                space: self.space,
                address: new_address,
            })
    }

    pub fn checked_offset_from(&self, base: Address) -> Option<u64> {
        if self.space != base.space {
            return None;
        }
        self.address.checked_offset_from(base.address)
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
}

pub trait AddressRangeExt<T> {
    fn difference<E>(self, excluded: E) -> impl Iterator<Item = RangeInclusive<T>>
    where
        Self: Sized,
        E: IntoIterator,
        E::Item: AddressRangeExt<T>;

    fn first(&self) -> T;

    fn last(&self) -> T;

    fn size(&self) -> Option<u64>;

    fn contains_address(&self, address: T) -> bool;

    fn is_empty(&self) -> bool;

    fn inclusive(&self) -> RangeInclusive<T>;
}

trait AddressDifference: Add<usize, Output = Self> + Copy + Ord + Sub<usize, Output = Self> {
    fn checked_offset_from(self, base: Self) -> Option<u64>;
}

impl AddressDifference for RawAddress {
    fn checked_offset_from(self, base: Self) -> Option<u64> {
        RawAddress::checked_offset_from(&self, base)
    }
}

impl AddressDifference for Address {
    fn checked_offset_from(self, base: Self) -> Option<u64> {
        Address::checked_offset_from(&self, base)
    }
}

impl<T: AddressDifference> AddressRangeExt<T> for RangeInclusive<T> {
    fn difference<E>(self, excluded: E) -> impl Iterator<Item = RangeInclusive<T>>
    where
        E: IntoIterator,
        E::Item: AddressRangeExt<T>,
    {
        // NOTE: assumes exclusions are ordered
        let mut excluded = excluded.into_iter().peekable();
        let mut remainder = (!self.is_empty()).then(|| (*self.start(), *self.end()));

        iter::from_fn(move || {
            loop {
                let (start, end) = remainder.take()?;

                while excluded
                    .peek()
                    .is_some_and(|range| range.is_empty() || range.last() < start)
                {
                    excluded.next();
                }

                let Some(exclusion) = excluded.peek() else {
                    return Some(start..=end);
                };
                let exclusion_start = exclusion.first();
                if exclusion_start > end {
                    return Some(start..=end);
                }
                let exclusion_end = exclusion.last();
                if exclusion_start > start {
                    remainder = (exclusion_end < end).then_some((exclusion_end + 1usize, end));
                    if remainder.is_some() {
                        excluded.next();
                    }
                    return Some(start..=(exclusion_start - 1usize));
                }
                if exclusion_end < end {
                    remainder = Some((exclusion_end + 1usize, end));
                    excluded.next();
                }
            }
        })
    }

    fn first(&self) -> T {
        *self.start()
    }

    fn last(&self) -> T {
        *self.end()
    }

    fn size(&self) -> Option<u64> {
        if RangeInclusive::is_empty(self) {
            return Some(0);
        }
        (*self.end())
            .checked_offset_from(*self.start())
            .and_then(|span| span.checked_add(1))
    }

    fn contains_address(&self, address: T) -> bool {
        self.contains(&address)
    }

    fn is_empty(&self) -> bool {
        RangeInclusive::is_empty(self)
    }

    fn inclusive(&self) -> RangeInclusive<T> {
        self.clone()
    }
}

impl<T: AddressDifference> AddressRangeExt<T> for Range<T> {
    fn difference<E>(self, excluded: E) -> impl Iterator<Item = RangeInclusive<T>>
    where
        E: IntoIterator,
        E::Item: AddressRangeExt<T>,
    {
        (!self.is_empty())
            .then(|| (self.inclusive(), excluded))
            .into_iter()
            .flat_map(|(range, excluded)| range.difference(excluded))
    }

    fn first(&self) -> T {
        self.start
    }

    fn last(&self) -> T {
        self.end - 1usize
    }

    fn size(&self) -> Option<u64> {
        if Range::is_empty(self) {
            return Some(0);
        }
        self.end.checked_offset_from(self.start)
    }

    fn contains_address(&self, address: T) -> bool {
        self.contains(&address)
    }

    fn is_empty(&self) -> bool {
        Range::is_empty(self)
    }

    fn inclusive(&self) -> RangeInclusive<T> {
        self.start..=(self.end - 1usize)
    }
}

#[derive(
    Debug, Clone, Default, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
pub struct AddressTable {
    address: Address,
    element_size: u32,
    element_count: u32,
    shift: u8,
}

impl AddressTable {
    pub fn new(address: Address, element_size: u32) -> Self {
        Self {
            address,
            element_size,
            element_count: 0,
            shift: 0,
        }
    }

    pub fn with_element_count(mut self, element_count: u32) -> Self {
        self.set_element_count(element_count);
        self
    }

    pub fn with_shift(mut self, shift: u8) -> Self {
        self.shift = shift;
        self
    }

    pub fn address(&self) -> Address {
        self.address
    }

    pub fn element_size(&self) -> u32 {
        self.element_size
    }

    pub fn element_count(&self) -> u32 {
        self.element_count
    }

    pub fn set_element_count(&mut self, count: u32) {
        self.element_count = count;
    }

    pub fn shift(&self) -> u8 {
        self.shift
    }

    pub fn size(&self) -> u64 {
        self.element_count as u64 * self.element_size as u64
    }

    pub fn entry_address(&self, index: u32) -> Address {
        self.address + index as u64 * self.element_size as u64
    }

    pub fn range(&self) -> Option<AddressRange> {
        let size = self.size();
        if size == 0 {
            return None;
        }
        let start = self.address.raw_address();
        Some(AddressRange::new(
            self.address.space(),
            start,
            start + size - 1u64,
        ))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn empty_address_table_has_no_range() {
        let table = AddressTable::new(Address::from(0x1000u64), 4);
        assert_eq!(table.range(), None);
    }

    #[test]
    fn zero_element_size_table_has_no_range() {
        let mut table = AddressTable::new(Address::from(0x1000u64), 0);
        table.set_element_count(4);
        assert_eq!(table.range(), None);
    }

    #[test]
    fn raw_address_aligns_in_both_directions() {
        let address = RawAddress::from(0x1003u64);
        assert_eq!(address.align(4), RawAddress::from(0x1004u64));
        assert_eq!(address.align_down(4), RawAddress::from(0x1000u64));
    }

    #[test]
    fn inclusive_size() {
        assert_eq!(
            (RawAddress::from(0u64)..=RawAddress::from(9u64)).size(),
            Some(10)
        );
        assert_eq!(
            (RawAddress::from(5u64)..=RawAddress::from(5u64)).size(),
            Some(1)
        );
        assert_eq!((RawAddress::zero()..=RawAddress::MAX).size(), None);
        assert_eq!(
            (RawAddress::from(5u64)..=RawAddress::from(3u64)).size(),
            Some(0)
        );
    }

    #[test]
    fn inclusive_bounds() {
        let range = RawAddress::from(4u64)..=RawAddress::from(8u64);
        assert_eq!(range.first(), RawAddress::from(4u64));
        assert_eq!(range.last(), RawAddress::from(8u64));
        assert!(!range.is_empty());
        assert!(range.contains_address(RawAddress::from(4u64)));
        assert!(range.contains_address(RawAddress::from(8u64)));
        assert!(!range.contains_address(RawAddress::from(9u64)));
        assert_eq!(
            range.inclusive(),
            RawAddress::from(4u64)..=RawAddress::from(8u64)
        );
    }

    #[test]
    fn exclusive_size() {
        assert_eq!(
            (RawAddress::from(0u64)..RawAddress::from(10u64)).size(),
            Some(10)
        );
        assert_eq!(
            (RawAddress::from(5u64)..RawAddress::from(5u64)).size(),
            Some(0)
        );
    }

    #[test]
    fn exclusive_bounds() {
        let range = RawAddress::from(4u64)..RawAddress::from(9u64);
        assert_eq!(range.first(), RawAddress::from(4u64));
        assert_eq!(range.last(), RawAddress::from(8u64));
        assert!(!range.is_empty());
        assert!(range.contains_address(RawAddress::from(4u64)));
        assert!(!range.contains_address(RawAddress::from(9u64)));
        assert_eq!(
            range.inclusive(),
            RawAddress::from(4u64)..=RawAddress::from(8u64)
        );
        assert!(
            (RawAddress::zero()..RawAddress::zero())
                .difference(iter::empty::<RangeInclusive<RawAddress>>())
                .next()
                .is_none()
        );
    }

    fn range(space: u8, start: u64, end: u64) -> AddressRange {
        AddressRange::new(
            AddressSpaceId::from(space),
            RawAddress::from(start),
            RawAddress::from(end),
        )
    }

    #[test]
    fn address_range_contains_and_size() {
        let span = range(0, 0x1000, 0x1fff);

        assert!(span.contains(RawAddress::from(0x1000u64)));
        assert!(span.contains(RawAddress::from(0x1fffu64)));
        assert!(!span.contains(RawAddress::from(0xfffu64)));
        assert!(!span.contains(RawAddress::from(0x2000u64)));
        assert_eq!(span.size(), 0x1000);
        assert!(!span.is_empty());
    }

    #[test]
    fn address_range_from_size_rejects_empty_and_overflowing_extents() {
        let start = Address::from(0x1000u64);
        assert_eq!(
            AddressRange::from_size(start, 0x20),
            Some(range(0, 0x1000, 0x101f))
        );
        assert_eq!(AddressRange::from_size(start, 0), None);
        assert_eq!(AddressRange::from_size(Address::from(u64::MAX), 2), None);
    }

    #[test]
    fn address_range_intersects() {
        let base = range(0, 0x1000, 0x1fff);

        assert!(base.intersects(&range(0, 0x1fff, 0x2fff)));
        assert!(base.intersects(&range(0, 0x1400, 0x14ff)));
        assert!(base.intersects(&range(0, 0x0, 0x1000)));
        assert!(!base.intersects(&range(0, 0x2000, 0x2fff)));
        assert!(!base.intersects(&range(0, 0x0, 0xfff)));
        assert!(!base.intersects(&range(1, 0x1000, 0x1fff)));
    }

    #[test]
    fn address_range_set_ranges_round_trip() {
        let mut covered = AddressRangeSet::new();
        covered.insert_range(range(0, 0x1000, 0x1fff));
        covered.insert_range(range(0, 0x2000, 0x2fff));
        covered.insert_range(range(1, 0x1000, 0x10ff));

        let ranges = covered.ranges().collect::<Vec<_>>();

        assert_eq!(
            ranges,
            vec![range(0, 0x1000, 0x2fff), range(1, 0x1000, 0x10ff)]
        );
    }

    #[test]
    fn address_range_set_intersection_agrees_with_brute_force() {
        let mut covered = AddressRangeSet::new();
        covered.insert_range(range(0, 0x1000, 0x1fff));
        covered.insert_range(range(0, 0x4000, 0x4fff));
        covered.insert_range(range(2, 0x0, 0xff));

        let candidates = [
            range(0, 0x0, 0xfff),
            range(0, 0x0, 0x1000),
            range(0, 0x2000, 0x3fff),
            range(0, 0x4fff, 0x5fff),
            range(1, 0x1000, 0x1fff),
            range(2, 0xff, 0x1ff),
        ];

        for candidate in candidates {
            let brute = covered.ranges().any(|span| span.intersects(&candidate));
            assert_eq!(covered.intersects_range(&candidate), brute);

            let mut other = AddressRangeSet::new();
            other.insert_range(candidate);
            assert_eq!(covered.intersects(&other), brute);
        }
    }

    #[test]
    fn raw_address_range_set_preserves_set_operations() {
        let mut left = RawAddressRangeSet::new();
        left.insert_range(RawAddress::from(1u64)..=RawAddress::from(5u64));
        left.insert_range(RawAddress::from(10u64)..=RawAddress::from(12u64));
        let mut right = RawAddressRangeSet::new();
        right.insert_range(RawAddress::from(4u64)..=RawAddress::from(10u64));

        let offsets = |set: RawAddressRangeSet| {
            set.iter()
                .map(|address| address.offset())
                .collect::<Vec<_>>()
        };

        assert_eq!(offsets(left.difference(&right)), vec![1, 2, 3, 11, 12]);
        assert_eq!(offsets(left.intersection(&right)), vec![4, 5, 10]);
        assert_eq!(
            offsets(left.symmetric_difference(&right)),
            vec![1, 2, 3, 6, 7, 8, 9, 11, 12]
        );
        assert_eq!(offsets(left.union(&right)), (1u64..=12).collect::<Vec<_>>());
        assert_eq!(
            left.span(),
            Some(RawAddress::from(1u64)..=RawAddress::from(12u64))
        );
    }

    #[test]
    fn raw_address_range_set_difference_handles_spanning_exclusions() {
        let mut included = RawAddressRangeSet::new();
        included.insert_range(RawAddress::from(0u64)..=RawAddress::from(10u64));
        included.insert_range(RawAddress::from(20u64)..=RawAddress::from(30u64));

        let mut excluded = RawAddressRangeSet::new();
        excluded.insert_range(RawAddress::from(0u64)..=RawAddress::from(0u64));
        excluded.insert_range(RawAddress::from(3u64)..=RawAddress::from(5u64));
        excluded.insert_range(RawAddress::from(8u64)..=RawAddress::from(22u64));
        excluded.insert_range(RawAddress::from(30u64)..=RawAddress::from(u64::MAX));

        assert_eq!(
            included.difference(&excluded).ranges().collect::<Vec<_>>(),
            vec![
                RawAddress::from(1u64)..=RawAddress::from(2u64),
                RawAddress::from(6u64)..=RawAddress::from(7u64),
                RawAddress::from(23u64)..=RawAddress::from(29u64),
            ]
        );
    }

    #[test]
    fn raw_address_map_bounds_and_overlaps_preserve_point_semantics() {
        let mut map = RawAddressMap::new();
        map.insert_range(RawAddress::from(2u64)..=RawAddress::from(5u64), 1u32);
        map.insert_range(RawAddress::from(8u64)..=RawAddress::from(10u64), 2u32);
        assert_eq!(map.insert(RawAddress::from(4u64), 3), Some(1));
        assert_eq!(map.run_count(), 4);

        let bounded = map
            .range((
                Bound::Excluded(RawAddress::from(2u64)),
                Bound::Excluded(RawAddress::from(9u64)),
            ))
            .map(|(address, value)| (address.offset(), value))
            .collect::<Vec<_>>();

        assert_eq!(bounded, vec![(3, 1), (4, 3), (5, 1), (8, 2)]);
        assert_eq!(
            map.max_in_range(RawAddress::from(4u64)..=RawAddress::from(8u64)),
            Some(3)
        );
        assert_eq!(map.remove(RawAddress::from(4u64)), Some(3));
        assert_eq!(map.get(RawAddress::from(4u64)), None);
        assert!(
            map.range((
                Bound::Excluded(RawAddress::MAX),
                Bound::<RawAddress>::Unbounded,
            ))
            .next()
            .is_none()
        );
    }
}
