// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

use std::mem;
use std::ops::Deref;

pub struct PredefinedType<'a> {
    pub name: &'a str,
    pub signed: bool,
    pub bits: u32,
}

static PREDEFINED_TYPES: [PredefinedType; 8] = [
    PredefinedType {
        name: "int16_t",
        signed: true,
        bits: 16,
    },
    PredefinedType {
        name: "int32_t",
        signed: true,
        bits: 32,
    },
    PredefinedType {
        name: "int64_t",
        signed: true,
        bits: 64,
    },
    PredefinedType {
        name: "int8_t",
        signed: true,
        bits: 8,
    },
    PredefinedType {
        name: "uint16_t",
        signed: false,
        bits: 16,
    },
    PredefinedType {
        name: "uint32_t",
        signed: false,
        bits: 32,
    },
    PredefinedType {
        name: "uint64_t",
        signed: false,
        bits: 64,
    },
    PredefinedType {
        name: "uint8_t",
        signed: false,
        bits: 8,
    },
];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PredefinedTypeRef {
    index: usize,
}

impl Deref for PredefinedTypeRef {
    type Target = PredefinedType<'static>;

    fn deref(&self) -> &'static Self::Target {
        &PREDEFINED_TYPES[self.index]
    }
}

pub struct PredefinedTypes;

impl PredefinedTypes {
    pub fn lookup(name: &str) -> Option<PredefinedTypeRef> {
        match PREDEFINED_TYPES.binary_search_by(|bt| bt.name.partial_cmp(name).unwrap()) {
            Ok(i) => Some(PredefinedTypeRef { index: i }),
            Err(_) => None,
        }
    }

    pub fn find_type_with_repr(repr_bits: u32, is_signed: bool) -> Option<PredefinedTypeRef> {
        PREDEFINED_TYPES
            .iter()
            .position(|p| p.bits == repr_bits && p.signed == is_signed)
            .map(|index| PredefinedTypeRef { index })
    }

    pub fn find_type_for_value(value_repr_bits: u32, is_signed: bool) -> Option<PredefinedTypeRef> {
        let mut type_repr_bits = 0;
        for b in [8, 16, 32, 64] {
            if b > value_repr_bits || (b == value_repr_bits && !is_signed) {
                type_repr_bits = b;
                break;
            }
        }

        Self::find_type_with_repr(type_repr_bits, is_signed)
    }

    pub fn find_common_type(
        mut t0: PredefinedTypeRef,
        mut t1: PredefinedTypeRef,
    ) -> Option<PredefinedTypeRef> {
        if !t0.signed {
            mem::swap(&mut t0, &mut t1);
        }

        if t0.signed {
            if t1.signed {
                if t0.bits >= t1.bits {
                    Some(t0)
                } else {
                    Some(t1)
                }
            } else if t1.bits >= t0.bits {
                Self::find_type_for_value(t1.bits + 1, true)
            } else {
                Some(t0)
            }
        } else {
            assert!(!t1.signed);
            if t0.bits >= t1.bits {
                Some(t0)
            } else {
                Some(t1)
            }
        }
    }
}

pub struct PredefinedConstant<'a> {
    pub name: &'a str,
    pub value_type: &'a str,
    pub sizeof_deps: Option<&'a [&'a str]>, // Input sizeof(...) needed for calculating the value at runtime.
    pub predefined_constant_deps: Option<&'a [&'a str]>,
}

impl<'a> PredefinedConstant<'a> {
    pub fn is_primary(&self) -> bool {
        self.predefined_constant_deps.is_none()
    }
}

static PREDEFINED_CONSTANTS: [PredefinedConstant; 32] = [
    PredefinedConstant {
        name: "HASH_COUNT",
        value_type: "uint32_t",
        sizeof_deps: None,
        predefined_constant_deps: None,
    },
    PredefinedConstant {
        name: "IMPLEMENTATION_PCR",
        value_type: "uint32_t",
        sizeof_deps: None,
        predefined_constant_deps: None,
    },
    PredefinedConstant {
        name: "LABEL_MAX_BUFFER",
        value_type: "uint16_t",
        sizeof_deps: None,
        predefined_constant_deps: Some(&["MAX_DIGEST_SIZE", "MAX_ECC_KEY_BYTES"]),
    },
    PredefinedConstant {
        name: "MAX_ACTIVE_SESSIONS",
        value_type: "uint32_t",
        sizeof_deps: None,
        predefined_constant_deps: None,
    },
    PredefinedConstant {
        name: "MAX_ACT_DATA",
        value_type: "uint32_t",
        sizeof_deps: Some(&["TPMS_ACT_DATA"]),
        predefined_constant_deps: Some(&["MAX_CAP_DATA"]),
    },
    PredefinedConstant {
        name: "MAX_AC_CAPABILITIES",
        value_type: "uint32_t",
        sizeof_deps: Some(&["TPMS_AC_OUTPUT"]),
        predefined_constant_deps: Some(&["MAX_CAP_DATA"]),
    },
    PredefinedConstant {
        name: "MAX_ALG_LIST_SIZE",
        value_type: "uint32_t",
        sizeof_deps: None,
        predefined_constant_deps: None,
    },
    PredefinedConstant {
        name: "MAX_CAP_ALGS",
        value_type: "uint32_t",
        sizeof_deps: Some(&["TPMS_ALG_PROPERTY"]),
        predefined_constant_deps: Some(&["MAX_CAP_DATA"]),
    },
    PredefinedConstant {
        name: "MAX_CAP_BUFFER",
        value_type: "uint32_t",
        sizeof_deps: None,
        predefined_constant_deps: None,
    },
    PredefinedConstant {
        name: "MAX_CAP_CC",
        value_type: "uint32_t",
        sizeof_deps: Some(&["TPM_CC"]),
        predefined_constant_deps: Some(&["MAX_CAP_DATA"]),
    },
    PredefinedConstant {
        name: "MAX_CAP_DATA",
        value_type: "uint32_t",
        sizeof_deps: Some(&["TPM_CAP"]),
        predefined_constant_deps: Some(&["MAX_CAP_BUFFER"]),
    },
    PredefinedConstant {
        name: "MAX_CAP_HANDLES",
        value_type: "uint32_t",
        sizeof_deps: Some(&["TPM_HANDLE"]),
        predefined_constant_deps: Some(&["MAX_CAP_DATA"]),
    },
    PredefinedConstant {
        name: "MAX_CONTEXT_SIZE",
        value_type: "uint16_t",
        sizeof_deps: None,
        predefined_constant_deps: None,
    },
    PredefinedConstant {
        name: "MAX_DIGEST_BUFFER",
        value_type: "uint16_t",
        sizeof_deps: None,
        predefined_constant_deps: None,
    },
    PredefinedConstant {
        name: "MAX_DIGEST_SIZE",
        value_type: "uint16_t",
        sizeof_deps: None,
        predefined_constant_deps: Some(&[]),
    },
    PredefinedConstant {
        name: "MAX_ECC_CURVES",
        value_type: "uint32_t",
        sizeof_deps: Some(&["TPM_ECC_CURVE"]),
        predefined_constant_deps: Some(&["MAX_CAP_DATA"]),
    },
    PredefinedConstant {
        name: "MAX_ECC_KEY_BYTES",
        value_type: "uint16_t",
        sizeof_deps: None,
        predefined_constant_deps: Some(&[]),
    },
    PredefinedConstant {
        name: "MAX_LOADED_OBJECTS",
        value_type: "uint32_t",
        sizeof_deps: None,
        predefined_constant_deps: None,
    },
    PredefinedConstant {
        name: "MAX_NV_BUFFER_SIZE",
        value_type: "uint16_t",
        sizeof_deps: None,
        predefined_constant_deps: None,
    },
    PredefinedConstant {
        name: "MAX_NV_INDEX_SIZE",
        value_type: "uint16_t",
        sizeof_deps: None,
        predefined_constant_deps: None,
    },
    PredefinedConstant {
        name: "MAX_PCR_PROPERTIES",
        value_type: "uint32_t",
        sizeof_deps: Some(&["TPMS_TAGGED_PCR_SELECT"]),
        predefined_constant_deps: Some(&["MAX_CAP_DATA"]),
    },
    PredefinedConstant {
        name: "MAX_RSA_KEY_BYTES",
        value_type: "uint16_t",
        sizeof_deps: None,
        predefined_constant_deps: None,
    },
    PredefinedConstant {
        name: "MAX_SYM_BLOCK_SIZE",
        value_type: "uint16_t",
        sizeof_deps: None,
        predefined_constant_deps: Some(&[]),
    },
    PredefinedConstant {
        name: "MAX_SYM_DATA",
        value_type: "uint32_t",
        sizeof_deps: None,
        predefined_constant_deps: Some(&[]),
    },
    PredefinedConstant {
        name: "MAX_SYM_KEY_BYTES",
        value_type: "uint16_t",
        sizeof_deps: None,
        predefined_constant_deps: Some(&["MAX_DIGEST_SIZE"]),
    },
    PredefinedConstant {
        name: "MAX_TAGGED_POLICIES",
        value_type: "uint32_t",
        sizeof_deps: Some(&["TPMS_TAGGED_POLICY"]),
        predefined_constant_deps: Some(&["MAX_CAP_DATA"]),
    },
    PredefinedConstant {
        name: "MAX_TPM_PROPERTIES",
        value_type: "uint32_t",
        sizeof_deps: Some(&["TPMS_TAGGED_PROPERTY"]),
        predefined_constant_deps: Some(&["MAX_CAP_DATA"]),
    },
    PredefinedConstant {
        name: "PCR_SELECT_MAX",
        value_type: "uint8_t",
        sizeof_deps: None,
        predefined_constant_deps: Some(&["IMPLEMENTATION_PCR"]),
    },
    PredefinedConstant {
        name: "PCR_SELECT_MIN",
        value_type: "uint8_t",
        sizeof_deps: None,
        predefined_constant_deps: Some(&["PLATFORM_PCR"]),
    },
    PredefinedConstant {
        name: "PLATFORM_PCR",
        value_type: "uint32_t",
        sizeof_deps: None,
        predefined_constant_deps: None,
    },
    PredefinedConstant {
        name: "PRIVATE_VENDOR_SPECIFIC_BYTES",
        value_type: "uint16_t",
        sizeof_deps: None,
        predefined_constant_deps: None,
    },
    PredefinedConstant {
        name: "RSA_PRIVATE_SIZE",
        value_type: "uint16_t",
        sizeof_deps: None,
        predefined_constant_deps: None,
    },
];

pub struct PredefinedConstants;

impl PredefinedConstants {
    pub fn lookup(name: &str) -> Option<PredefinedConstantRef> {
        match PREDEFINED_CONSTANTS.binary_search_by(|bt| bt.name.partial_cmp(name).unwrap()) {
            Ok(i) => Some(PredefinedConstantRef { index: i }),
            Err(_) => None,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct PredefinedConstantRef {
    index: usize,
}

impl Deref for PredefinedConstantRef {
    type Target = PredefinedConstant<'static>;

    fn deref(&self) -> &'static Self::Target {
        &PREDEFINED_CONSTANTS[self.index]
    }
}
