use serde::{Deserialize, Deserializer};

use super::RouteFlags;

type RouteAttrBitframe = u64;

#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
/// A dedicated bitset to represent the flags
/// Accept multiple serde formats
pub struct RouteAttr(RouteAttrBitframe);

impl RouteAttr {
    #[must_use]
    pub const fn from_u64(value: RouteAttrBitframe) -> Self {
        Self(value)
    }
    // #[inline]
    // pub fn toggle_flag(&mut self, flag: RouteFlags) {
    //     self.0 ^= 1 << flag as u64;
    // }
    #[inline]
    pub const fn set_flag(&mut self, flag: RouteFlags) {
        self.0 |= 1 << flag as RouteAttrBitframe;
    }
    #[inline]
    #[must_use]
    pub fn from_flags(flags: &[RouteFlags]) -> Self {
        let mut ra = Self::default();
        for flag in flags {
            ra.set_flag(*flag);
        }
        ra
    }
    #[inline]
    #[must_use]
    pub const fn contains(&self, flag: RouteFlags) -> bool {
        self.0 & (1 << flag as RouteAttrBitframe) != 0
    }
}

impl From<RouteFlags> for RouteAttr {
    fn from(flag: RouteFlags) -> Self {
        Self::from_flags(std::slice::from_ref(&flag))
    }
}

impl core::fmt::Debug for RouteAttr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RouteAttr({})", self.0)
    }
}

impl<'de> Deserialize<'de> for RouteAttr {
    fn deserialize<D>(de: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum In {
            U64(u64),
            Seq(Vec<RouteFlags>),
        }

        match In::deserialize(de)? {
            In::U64(n) => Ok(Self::from_u64(n)),
            In::Seq(v) => Ok(Self::from_flags(&v)),
        }
    }
}
