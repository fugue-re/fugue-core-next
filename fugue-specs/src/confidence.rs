use std::fmt::Display;

use ordered_float::OrderedFloat;
#[cfg(feature = "rkyv")]
use rkyv::rancor::Fallible;
#[cfg(feature = "rkyv")]
use rkyv::{Archive, Place, Serialize as RkyvSerialize};
use serde::{Deserialize, Serialize};

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[repr(transparent)]
pub struct Confidence(OrderedFloat<f32>);

impl Display for Confidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = self.0 .0;
        let kind = if value == 1f32 {
            "certain"
        } else if value >= 0.8f32 {
            "somewhat certain"
        } else if value >= 0.6f32 {
            "somewhat uncertain"
        } else if value >= 0.4f32 {
            "uncertain"
        } else {
            "very uncertain"
        };
        write!(f, "{kind} ~ {value:.2}")
    }
}

impl Default for Confidence {
    fn default() -> Self {
        Self::certain()
    }
}

impl From<f32> for Confidence {
    fn from(value: f32) -> Self {
        Self::new(value)
    }
}

impl From<Confidence> for f32 {
    fn from(value: Confidence) -> Self {
        value.0 .0
    }
}

#[cfg(feature = "rkyv")]
#[repr(transparent)]
pub struct ArchivedConfidence(rkyv::Archived<f32>);

#[cfg(feature = "rkyv")]
unsafe impl rkyv::Portable for ArchivedConfidence {}
#[cfg(feature = "rkyv")]
unsafe impl rkyv::traits::NoUndef for ArchivedConfidence {}

#[cfg(feature = "rkyv")]
impl Archive for Confidence {
    type Archived = ArchivedConfidence;
    type Resolver = ();

    fn resolve(&self, _: Self::Resolver, out: Place<Self::Archived>) {
        out.write(ArchivedConfidence(
            rkyv::primitive::ArchivedF32::from_native(self.0 .0),
        ));
    }
}

#[cfg(feature = "rkyv")]
impl<S: Fallible + ?Sized> RkyvSerialize<S> for Confidence {
    fn serialize(&self, _: &mut S) -> Result<Self::Resolver, S::Error> {
        Ok(())
    }
}

#[cfg(feature = "rkyv")]
impl<D: Fallible + ?Sized> rkyv::Deserialize<Confidence, D> for ArchivedConfidence {
    fn deserialize(&self, _: &mut D) -> Result<Confidence, D::Error> {
        Ok(Confidence::new(self.0.to_native()))
    }
}

impl Confidence {
    pub fn new(value: f32) -> Self {
        Self(OrderedFloat(value.clamp(0f32, 1f32)))
    }

    pub fn certain() -> Self {
        Self::new(1f32)
    }

    pub fn somewhat_certain() -> Self {
        Self::new(0.8f32)
    }

    pub fn somewhat_uncertain() -> Self {
        Self::new(0.6f32)
    }

    pub fn uncertain() -> Self {
        Self::new(0.4f32)
    }

    pub fn very_uncertain() -> Self {
        Self::new(0.2f32)
    }

    pub fn merge_max(&mut self, other: Confidence) {
        *self = other.max(*self);
    }
}

impl<'de> Deserialize<'de> for Confidence {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Confidence {
            Float(f32),
            String(ConfidenceKinds),
        }

        #[derive(Deserialize)]
        enum ConfidenceKinds {
            #[serde(rename = "certain", alias = "very high")]
            Certain,
            #[serde(rename = "somewhat certain", alias = "high")]
            SomewhatCertain,
            #[serde(rename = "somewhat uncertain", alias = "medium")]
            SomewhatUncertain,
            #[serde(rename = "uncertain", alias = "low")]
            Uncertain,
            #[serde(rename = "very uncertain", alias = "very low")]
            VeryUncertain,
        }

        let value = Confidence::deserialize(deserializer)?;

        match value {
            Confidence::Float(value) => {
                if (0f32..=1f32).contains(&value) {
                    Ok(Self(value.into()))
                } else {
                    Err(serde::de::Error::custom(format!(
                        "confidence must be between 0 and 1; got {value}",
                    )))
                }
            }
            Confidence::String(value) => match value {
                ConfidenceKinds::Certain => Ok(Self::certain()),
                ConfidenceKinds::SomewhatCertain => Ok(Self::somewhat_certain()),
                ConfidenceKinds::SomewhatUncertain => Ok(Self::somewhat_uncertain()),
                ConfidenceKinds::Uncertain => Ok(Self::uncertain()),
                ConfidenceKinds::VeryUncertain => Ok(Self::very_uncertain()),
            },
        }
    }
}
