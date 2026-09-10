// SPDX-License-Identifier: Apache-2.0

//! SNP certificate table GUIDs (`CertType`).
//!
//! GUID values match the AMD SEV-SNP certificate table specification. Unknown
//! GUIDs are represented as [`CertType::OTHER`].

use crate::{
    parser::{ByteParser, Decoder, Encoder},
    util::parser_helper::{ReadExt, WriteExt},
};
use std::{
    convert::TryFrom,
    fmt::{self, Display, Formatter},
    io::{Read, Write},
};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Certificate type GUID for SNP certificate table entries.
///
/// Standard entries (ARK, ASK, VCEK, VLEK, CRL) use fixed AMD GUIDs.
/// [`CertType::Empty`] terminates a kernel cert table. Custom vendor entries
/// use [`CertType::OTHER`].
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub enum CertType {
    /// Empty or closing entry for the CertTable
    #[default]
    Empty,

    /// AMD Root Signing Key (ARK) certificate
    ARK,

    /// AMD SEV Signing Key (ASK) certificate
    ASK,

    /// Versioned Chip Endorsement Key (VCEK) certificate
    VCEK,

    /// Versioned Loaded Endorsement Key (VLEK) certificate
    VLEK,

    /// Certificate Revocation List (CRLs) certificate(s)
    CRL,

    /// Other (Specify GUID)
    OTHER(uuid::Uuid),
}

impl Display for CertType {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let guid = match self {
            CertType::Empty => "00000000-0000-0000-0000-000000000000".to_string(),
            CertType::ARK => "c0b406a4-a803-4952-9743-3fb6014cd0ae".to_string(),
            CertType::ASK => "4ab7b379-bbac-4fe4-a02f-05aef327c782".to_string(),
            CertType::VCEK => "63da758d-e664-4564-adc5-f4b93be8accd".to_string(),
            CertType::VLEK => "a8074bc2-a25a-483e-aae6-39c045a0b8a1".to_string(),
            CertType::CRL => "92f81bc3-5811-4d3d-97ff-d19f88dc67ea".to_string(),
            CertType::OTHER(guid) => guid.to_string(),
        };

        write!(f, "{}", guid)
    }
}

impl TryFrom<CertType> for uuid::Uuid {
    type Error = uuid::Error;
    fn try_from(value: CertType) -> Result<Self, Self::Error> {
        match value {
            CertType::Empty => uuid::Uuid::parse_str(&CertType::Empty.to_string()),
            CertType::ARK => uuid::Uuid::parse_str(&CertType::ARK.to_string()),
            CertType::ASK => uuid::Uuid::parse_str(&CertType::ASK.to_string()),
            CertType::VCEK => uuid::Uuid::parse_str(&CertType::VCEK.to_string()),
            CertType::VLEK => uuid::Uuid::parse_str(&CertType::VLEK.to_string()),
            CertType::CRL => uuid::Uuid::parse_str(&CertType::CRL.to_string()),
            CertType::OTHER(guid) => Ok(guid),
        }
    }
}

impl TryFrom<&uuid::Uuid> for CertType {
    type Error = uuid::Error;

    fn try_from(value: &uuid::Uuid) -> Result<Self, Self::Error> {
        Ok(match value.to_string().as_str() {
            "00000000-0000-0000-0000-000000000000" => CertType::Empty,
            "c0b406a4-a803-4952-9743-3fb6014cd0ae" => CertType::ARK,
            "4ab7b379-bbac-4fe4-a02f-05aef327c782" => CertType::ASK,
            "63da758d-e664-4564-adc5-f4b93be8accd" => CertType::VCEK,
            "a8074bc2-a25a-483e-aae6-39c045a0b8a1" => CertType::VLEK,
            "92f81bc3-5811-4d3d-97ff-d19f88dc67ea" => CertType::CRL,
            _ => CertType::OTHER(*value),
        })
    }
}

impl Ord for CertType {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match (self, other) {
            (Self::ARK, Self::ARK)
            | (Self::ASK, Self::ASK)
            | (Self::VCEK, Self::VCEK)
            | (Self::VLEK, Self::VLEK)
            | (Self::CRL, Self::CRL)
            | (Self::Empty, Self::Empty) => std::cmp::Ordering::Equal,
            (Self::OTHER(left), Self::OTHER(right)) => left.cmp(right),
            (Self::Empty, _) => std::cmp::Ordering::Greater,
            (_, Self::Empty) => std::cmp::Ordering::Less,
            (Self::OTHER(_), _) => std::cmp::Ordering::Greater,
            (_, Self::OTHER(_)) => std::cmp::Ordering::Less,
            (Self::CRL, _) => std::cmp::Ordering::Greater,
            (_, Self::CRL) => std::cmp::Ordering::Less,
            (Self::ASK, _) => std::cmp::Ordering::Greater,
            (_, Self::ASK) => std::cmp::Ordering::Less,
            (Self::VLEK, _) => std::cmp::Ordering::Greater,
            (_, Self::VLEK) => std::cmp::Ordering::Less,
            (Self::VCEK, _) => std::cmp::Ordering::Greater,
            (_, Self::VCEK) => std::cmp::Ordering::Less,
        }
    }
}

impl Encoder<()> for CertType {
    fn encode(&self, writer: &mut impl Write, _: ()) -> Result<(), std::io::Error> {
        let bytes = uuid::Uuid::try_from(self.clone())
            .map_err(|_| std::io::ErrorKind::InvalidData)?
            .into_bytes();
        writer.write_bytes(bytes, ())?;
        Ok(())
    }
}

impl Decoder<()> for CertType {
    fn decode(reader: &mut impl Read, _: ()) -> Result<Self, std::io::Error> {
        let bytes = reader.read_bytes()?;
        let uuid = uuid::Uuid::from_bytes(bytes);
        Ok(CertType::try_from(&uuid).map_err(|_| std::io::ErrorKind::InvalidData)?)
    }
}

impl ByteParser<()> for CertType {
    type Bytes = [u8; 16];
    const EXPECTED_LEN: Option<usize> = Some(16);
}

impl PartialOrd for CertType {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::ByteParser;
    use uuid::Uuid;

    #[test]
    fn test_cert_type_sort_vcek() {
        let mut certs: Vec<CertType> = vec![
            CertType::Empty,
            CertType::CRL,
            CertType::OTHER(Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap()),
            CertType::OTHER(Uuid::parse_str("33333333-3333-3333-3333-333333333333").unwrap()),
            CertType::OTHER(Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap()),
            CertType::ARK,
            CertType::ASK,
            CertType::VCEK,
        ];

        let sorted_certs: Vec<CertType> = vec![
            CertType::ARK,
            CertType::VCEK,
            CertType::ASK,
            CertType::CRL,
            CertType::OTHER(Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap()),
            CertType::OTHER(Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap()),
            CertType::OTHER(Uuid::parse_str("33333333-3333-3333-3333-333333333333").unwrap()),
            CertType::Empty,
        ];
        certs.sort();
        assert_eq!(certs, sorted_certs);
    }

    #[test]
    fn test_cert_type_sort_vlek() {
        let mut certs: Vec<CertType> = vec![
            CertType::Empty,
            CertType::CRL,
            CertType::OTHER(Uuid::parse_str("33333333-3333-3333-3333-333333333333").unwrap()),
            CertType::OTHER(Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap()),
            CertType::OTHER(Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap()),
            CertType::ARK,
            CertType::ASK,
            CertType::VLEK,
        ];

        let sorted_certs: Vec<CertType> = vec![
            CertType::ARK,
            CertType::VLEK,
            CertType::ASK,
            CertType::CRL,
            CertType::OTHER(Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap()),
            CertType::OTHER(Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap()),
            CertType::OTHER(Uuid::parse_str("33333333-3333-3333-3333-333333333333").unwrap()),
            CertType::Empty,
        ];
        certs.sort();
        assert_eq!(certs, sorted_certs);
    }

    #[test]
    fn test_cert_type_fmt() {
        let mut cert_type: CertType = CertType::Empty;
        let mut expected: &str = "00000000-0000-0000-0000-000000000000";

        assert_eq!(cert_type.to_string(), expected.to_string());

        cert_type = CertType::ARK;
        expected = "c0b406a4-a803-4952-9743-3fb6014cd0ae";

        assert_eq!(cert_type.to_string(), expected.to_string());

        cert_type = CertType::ASK;
        expected = "4ab7b379-bbac-4fe4-a02f-05aef327c782";

        assert_eq!(cert_type.to_string(), expected.to_string());

        cert_type = CertType::VCEK;
        expected = "63da758d-e664-4564-adc5-f4b93be8accd";

        assert_eq!(cert_type.to_string(), expected.to_string());

        cert_type = CertType::VLEK;
        expected = "a8074bc2-a25a-483e-aae6-39c045a0b8a1";

        assert_eq!(cert_type.to_string(), expected.to_string());

        cert_type = CertType::CRL;
        expected = "92f81bc3-5811-4d3d-97ff-d19f88dc67ea";

        assert_eq!(cert_type.to_string(), expected.to_string());
    }

    #[test]
    fn test_cert_type_conversion() {
        let ark_guid = Uuid::parse_str("c0b406a4-a803-4952-9743-3fb6014cd0ae").unwrap();
        let cert_type = CertType::try_from(&ark_guid).unwrap();
        assert_eq!(cert_type, CertType::ARK);

        let uuid = Uuid::try_from(CertType::ARK).unwrap();
        assert_eq!(uuid, ark_guid);
    }

    #[test]
    fn test_cert_type_deserialization() {
        let cert_types = vec![
            CertType::Empty,
            CertType::ARK,
            CertType::ASK,
            CertType::VCEK,
            CertType::VLEK,
            CertType::CRL,
            CertType::OTHER(Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap()),
        ];

        for cert_type in cert_types {
            let serialized = cert_type.to_bytes().unwrap();
            let deserialized = CertType::from_bytes(&serialized).unwrap();
            assert_eq!(cert_type, deserialized);
        }
    }

    #[test]
    fn test_cert_type_try_from_uuid() {
        let test_cases = vec![
            ("00000000-0000-0000-0000-000000000000", CertType::Empty),
            ("c0b406a4-a803-4952-9743-3fb6014cd0ae", CertType::ARK),
            ("4ab7b379-bbac-4fe4-a02f-05aef327c782", CertType::ASK),
            ("63da758d-e664-4564-adc5-f4b93be8accd", CertType::VCEK),
            ("a8074bc2-a25a-483e-aae6-39c045a0b8a1", CertType::VLEK),
            ("92f81bc3-5811-4d3d-97ff-d19f88dc67ea", CertType::CRL),
            (
                "11111111-1111-1111-1111-111111111111",
                CertType::OTHER(Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap()),
            ),
        ];

        for (uuid_str, expected_type) in test_cases {
            let uuid = Uuid::parse_str(uuid_str).unwrap();
            assert_eq!(CertType::try_from(&uuid).unwrap(), expected_type);
        }
    }

    #[test]
    fn test_cert_type_cmp_complete() {
        let mut cert_types = vec![
            CertType::ARK,
            CertType::VCEK,
            CertType::VLEK,
            CertType::ASK,
            CertType::CRL,
            CertType::Empty,
            CertType::OTHER(Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap()),
        ];

        let expected = vec![
            CertType::ARK,
            CertType::VCEK,
            CertType::VLEK,
            CertType::ASK,
            CertType::CRL,
            CertType::OTHER(Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap()),
            CertType::Empty,
        ];

        cert_types.sort();
        assert_eq!(cert_types, expected);
    }

    #[test]
    fn test_cert_type_to_uuid_conversion() {
        assert_eq!(
            Uuid::try_from(CertType::ARK).unwrap(),
            Uuid::parse_str("c0b406a4-a803-4952-9743-3fb6014cd0ae").unwrap()
        );
        assert_eq!(
            Uuid::try_from(CertType::ASK).unwrap(),
            Uuid::parse_str("4ab7b379-bbac-4fe4-a02f-05aef327c782").unwrap()
        );
        assert_eq!(
            Uuid::try_from(CertType::VCEK).unwrap(),
            Uuid::parse_str("63da758d-e664-4564-adc5-f4b93be8accd").unwrap()
        );
        assert_eq!(
            Uuid::try_from(CertType::VLEK).unwrap(),
            Uuid::parse_str("a8074bc2-a25a-483e-aae6-39c045a0b8a1").unwrap()
        );
        assert_eq!(
            Uuid::try_from(CertType::Empty).unwrap(),
            Uuid::parse_str("00000000-0000-0000-0000-000000000000").unwrap()
        );
        assert_eq!(
            Uuid::try_from(CertType::CRL).unwrap(),
            Uuid::parse_str("92f81bc3-5811-4d3d-97ff-d19f88dc67ea").unwrap()
        );
        assert_eq!(
            Uuid::try_from(CertType::OTHER(uuid::Uuid::max())).unwrap(),
            Uuid::parse_str("ffffffff-ffff-ffff-ffff-ffffffffffff").unwrap()
        );
    }
}
