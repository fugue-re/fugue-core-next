use std::fmt::{Debug, Display, LowerHex, UpperHex};
use std::num::ParseIntError;
use std::ops::{Add, AddAssign, Range, RangeBounds, RangeInclusive, Sub, SubAssign};
use std::str::FromStr;

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
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
    Deserialize,
    Serialize,
)]
#[rkyv(derive(PartialEq, Eq, PartialOrd, Ord, Hash))]
#[repr(transparent)]
pub struct RawAddress(u64);

impl Debug for RawAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl Display for RawAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        LowerHex::fmt(&self.0, f)
    }
}

impl UpperHex for RawAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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

    pub fn new(addr: impl Into<Self>) -> Self {
        addr.into()
    }

    pub const fn zero() -> Self {
        Self(0u64)
    }

    pub fn offset(&self) -> u64 {
        self.0
    }

    pub fn checked_add(&self, offset: impl Into<RawAddress>) -> Option<Self> {
        let offset = offset.into();
        self.0.checked_add(offset.0).map(Self)
    }

    pub fn checked_sub(&self, offset: impl Into<RawAddress>) -> Option<Self> {
        let offset = offset.into();
        self.0.checked_sub(offset.0).map(Self)
    }

    pub fn checked_offset_from(&self, base: RawAddress) -> Option<u64> {
        self.0.checked_sub(base.0)
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

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AddressWithContext {
    address: Address,
    context: ContextSet,
    confidence: Confidence,
}

impl Display for AddressWithContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
pub struct RawAddressRangeSet(RangeSetBlaze<u64>);

impl FromIterator<RawAddress> for RawAddressRangeSet {
    fn from_iter<T: IntoIterator<Item = RawAddress>>(iter: T) -> Self {
        Self(iter.into_iter().map(|addr| addr.offset()).collect())
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
        Self(iter.into_iter().map(|addr| addr.offset()).collect())
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
        Self(RangeSetBlaze::new())
    }

    pub fn insert(&mut self, address: impl Into<RawAddress>) -> bool {
        self.0.insert(address.into().offset())
    }

    pub fn insert_range(&mut self, range: impl Into<RangeInclusive<RawAddress>>) {
        let range = range.into();
        self.0
            .ranges_insert(range.start().offset()..=range.end().offset());
    }

    pub fn intersects_range(&self, range: impl Into<RangeInclusive<RawAddress>>) -> bool {
        let range = range.into();
        let start = range.start().offset();
        let end = range.end().offset();

        self.0
            .ranges()
            .any(|covered| *covered.start() <= end && start <= *covered.end())
    }

    pub fn insert_meta_range(&mut self, range: RangeInclusive<Address>) {
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

    pub fn remove(&mut self, address: impl Into<RawAddress>) {
        self.0.remove(address.into().offset());
    }

    pub fn contains(&self, address: impl Into<RawAddress>) -> bool {
        self.0.contains(address.into().offset())
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = RawAddress> + use<'_> {
        self.0.iter().map(RawAddress::from)
    }

    pub fn ranges(&self) -> impl Iterator<Item = RangeInclusive<RawAddress>> + use<'_> {
        self.0
            .ranges()
            .map(|r| RawAddress::from(*r.start())..=RawAddress::from(*r.end()))
    }

    pub fn clear(&mut self) {
        self.0.clear();
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RawAddressMap<V>(RangeMapBlaze<u64, V>)
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
        Self(RangeMapBlaze::new())
    }

    pub fn insert(&mut self, address: impl Into<RawAddress>, value: V) -> Option<V> {
        self.0.insert(address.into().offset(), value)
    }

    pub fn remove(&mut self, address: impl Into<RawAddress>) -> Option<V> {
        self.0.remove(address.into().offset())
    }

    pub fn contains_address(&self, address: impl Into<RawAddress>) -> bool {
        self.0.contains_key(address.into().offset())
    }

    pub fn get(&self, address: impl Into<RawAddress>) -> Option<&V> {
        self.0.get(address.into().offset())
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn clear(&mut self) {
        self.0.clear();
    }

    pub fn iter(&self) -> impl Iterator<Item = (RawAddress, &V)> {
        self.0.iter().map(|(k, v)| (RawAddress::from(k), v))
    }

    pub fn range(
        &self,
        range: impl RangeBounds<RawAddress>,
    ) -> impl Iterator<Item = (RawAddress, V)> {
        let start = range.start_bound().map(|addr| addr.offset());
        let end = range.end_bound().map(|addr| addr.offset());
        self.0
            .range((start, end))
            .map(|(k, v)| (RawAddress::from(k), v))
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
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
    Deserialize,
    Serialize,
)]
#[rkyv(derive(PartialEq, Eq, PartialOrd, Ord, Hash))]
pub struct Address {
    space: AddressSpaceId,
    address: RawAddress,
}

impl Debug for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{:#x}", self.space, self.address.offset())
    }
}

impl Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{:#x}", self.space, self.address.offset())
    }
}

impl LowerHex for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:", self.space)?;
        LowerHex::fmt(&self.address, f)
    }
}

impl UpperHex for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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

    pub fn in_space_bounds(&self, language: &Language) -> bool {
        self.address.in_space_bounds(language)
    }

    pub fn range_in_space_bounds(&self, language: &Language, size: usize) -> bool {
        self.address.range_in_space_bounds(language, size)
    }
}

pub trait AddressRange<T> {
    fn first(&self) -> T;

    fn last(&self) -> T;

    fn size(&self) -> Option<u64>;

    fn contains_address(&self, address: T) -> bool;

    fn is_empty(&self) -> bool;

    fn as_inclusive(&self) -> RangeInclusive<T>;
}

trait RangeAddress: Copy + Ord + Sub<usize, Output = Self> {
    fn checked_offset_from(self, base: Self) -> Option<u64>;
}

impl RangeAddress for RawAddress {
    fn checked_offset_from(self, base: Self) -> Option<u64> {
        RawAddress::checked_offset_from(&self, base)
    }
}

impl RangeAddress for Address {
    fn checked_offset_from(self, base: Self) -> Option<u64> {
        Address::checked_offset_from(&self, base)
    }
}

impl<T: RangeAddress> AddressRange<T> for RangeInclusive<T> {
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

    fn as_inclusive(&self) -> RangeInclusive<T> {
        self.clone()
    }
}

impl<T: RangeAddress> AddressRange<T> for Range<T> {
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

    fn as_inclusive(&self) -> RangeInclusive<T> {
        self.start..=(self.end - 1usize)
    }
}

#[cfg(test)]
mod test {
    use super::*;

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
            range.as_inclusive(),
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
            range.as_inclusive(),
            RawAddress::from(4u64)..=RawAddress::from(8u64)
        );
    }
}
