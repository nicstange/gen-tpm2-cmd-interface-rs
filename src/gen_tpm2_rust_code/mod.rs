// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

use crate::tcg_tpm2::structures;
use std::io::{self, Write};
use structures::tables::StructuresPartTablesIndex;

use super::tcg_tpm2;

pub struct Tpm2InterfaceRustCodeGenerator<'a> {
    tables: &'a tcg_tpm2::tables::Tables,
}

mod bits_impl;
mod camelcase_impl;
mod code_writer;
mod commands_impl;
mod constants_impl;
mod deps_impl;
mod expr_impl;
mod predefined_impl;
mod structure_impl;
mod type_impl;
mod union_impl;

impl<'a> Tpm2InterfaceRustCodeGenerator<'a> {
    pub fn new(tables: &'a tcg_tpm2::tables::Tables) -> Self {
        Self { tables }
    }

    pub fn generate<W: io::Write>(
        &self,
        out: W,
        enable_unaligned_accesses: bool,
        enable_enum_transmute: bool,
        enable_in_place_unmarshal: bool,
        enable_in_place_into_bufs_owner: bool,
        gen_commands_macro: bool,
    ) -> Result<(), io::Error> {
        let error_rc_insufficient = self
            .tables
            .structures
            .lookup_constant("TPM_RC_INSUFFICIENT")
            .unwrap();

        let mut out = code_writer::CodeWriter::new(out);
        let mut out = out.make_writer();
        write!(
            &mut out,
            "\
// TCG TPM2 Structures interface code
// Autogenerated with {} version {}

extern crate alloc;
use alloc::vec::Vec;
use alloc::boxed::Box;
use core::cmp;
use core::convert;
use core::default;
use core::mem;
use core::ops;
use core::ptr;
#[cfg(feature = \"zeroize\")]
use zeroize;

#[derive(Clone, Copy, Debug)]
pub enum TpmErr {{
    Rc(u32),
    InternalErr,
}}

#[derive(Clone, Debug)]
pub enum TpmBuffer<'a> {{
    Borrowed(&'a [u8]),
    #[cfg(not(feature = \"zeroize\"))]
    Owned(Vec<u8>),
    #[cfg(feature = \"zeroize\")]
    Owned(zeroize::Zeroizing<Vec<u8>>),
}}

impl<'a> TpmBuffer<'a> {{
    pub fn into_owned(self) -> Result<TpmBuffer<'static>, TpmErr> {{
        let o = match self {{
            Self::Borrowed(b) => {{
                let mut o = Vec::new();
                o.try_reserve_exact(b.len()).map_err(|_| TpmErr::Rc(TpmRc::MEMORY))?;
                o.extend_from_slice(&b);
                #[cfg(feature = \"zeroize\")]
                let o = zeroize::Zeroizing::from(o);
                o
            }},
            Self::Owned(o) => o,
        }};
        Ok(TpmBuffer::<'static>::Owned(o))
    }}
}}

impl<'a> ops::Deref for TpmBuffer<'a> {{
    type Target = [u8];

    fn deref(&self) -> &Self::Target {{
        match self {{
            Self::Borrowed(b) => b,
            Self::Owned(o) => &o,
        }}
    }}
}}

impl<'a> convert::From<&'a [u8]> for TpmBuffer<'a> {{
    fn from(value: &'a [u8]) -> Self {{
        Self::Borrowed(value)
    }}
}}

impl<'a> default::Default for TpmBuffer<'a> {{
    fn default() -> Self {{
        let o = Vec::new();
        #[cfg(feature = \"zeroize\")]
        let o = zeroize::Zeroizing::from(o);
        Self::Owned(o)
    }}
}}

impl<'a> PartialEq for TpmBuffer<'a> {{
    fn eq(&self, other: &Self) -> bool {{
        <Self as ops::Deref>::deref(self) == <Self as ops::Deref>::deref(other)
    }}
}}
",
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION")
        )?;

        if !self.tables.structures.predefined_constants_deps.is_empty() {
            self.gen_limits_def(&mut out)?;
        }

        writeln!(&mut out)?;
        writeln!(
            &mut out,
            "fn split_slice_at<T>(s: &[T], mid: usize) -> Result<(&[T], &[T]), TpmErr> {{"
        )?;
        let mut iout = out.make_indent();
        writeln!(&mut iout, "if s.len() < mid {{")?;
        self.format_error_return(&mut iout.make_indent(), None, error_rc_insufficient)?;
        writeln!(&mut iout, "}}")?;
        writeln!(&mut iout, "Ok(s.split_at(mid))")?;
        writeln!(&mut out, "}}")?;

        writeln!(&mut out)?;
        writeln!(
            &mut out,
            "fn split_slice_at_mut<T>(s: &mut [T], mid: usize) -> Result<(&mut [T], &mut [T]), TpmErr> {{"
        )?;
        let mut iout = out.make_indent();
        writeln!(&mut iout, "if s.len() < mid {{")?;
        writeln!(&mut iout.make_indent(), "return Err(TpmErr::InternalErr);")?;
        writeln!(&mut iout, "}}")?;
        writeln!(&mut iout, "Ok(s.split_at_mut(mid))")?;
        writeln!(&mut out, "}}")?;

        for b in [8, 16, 32, 64] {
            for s in ['u', 'i'] {
                let t = format!("{}{}", s, b);
                writeln!(&mut out)?;
                writeln!(&mut out,"fn unmarshal_{}(buf: &[u8]) -> Result<(&[u8], {}), TpmErr> {{",
                         &t, &t)?;
                let mut iout = out.make_indent();
                writeln!(&mut iout, "let (consumed, buf) = split_slice_at(buf, mem::size_of::<{}>())?;", &t)?;
                if enable_unaligned_accesses {
                    writeln!(&mut iout, "let p = consumed.as_ptr() as *const {};", &t)?;
                    writeln!(&mut iout, "let value = unsafe{{p.read_unaligned()}};")?;
                    writeln!(&mut iout, "let value = {}::from_be(value);", &t)?;
                } else {
                    writeln!(&mut iout, "let consumed: [u8; mem::size_of::<{}>()] = (&consumed as &[u8]).try_into().unwrap();",
                             &t)?;
                    writeln!(&mut iout, "let value = {}::from_be_bytes(consumed);", &t)?;
                }
                writeln!(&mut iout, "Ok((buf, value))")?;
                writeln!(&mut out, "}}")?;
            }
        }

        for b in [8, 16, 32, 64] {
            for s in ['u', 'i'] {
                let t = format!("{}{}", s, b);
                writeln!(&mut out)?;
                writeln!(
                    &mut out,
                    "fn marshal_{}<'a>(buf: &mut [u8], value: {}) -> Result<&mut [u8], TpmErr> {{",
                    &t, &t
                )?;
                let mut iout = out.make_indent();
                writeln!(
                    &mut iout,
                    "let (produced, buf) = buf.split_at_mut(mem::size_of::<{}>());",
                    &t
                )?;
                if enable_unaligned_accesses {
                    writeln!(&mut iout, "let value = {}::to_be(value);", &t)?;
                    writeln!(&mut iout, "let p = produced.as_mut_ptr() as *mut {};", &t)?;
                    writeln!(&mut iout, "unsafe{{p.write_unaligned(value)}};")?;
                } else {
                    writeln!(&mut iout, "let marshalled = value.to_be_bytes();")?;
                    writeln!(&mut iout, "produced.copy_from_slice(&marshalled);")?;
                }
                writeln!(&mut iout, "Ok(buf)")?;
                writeln!(&mut out, "}}")?;
            }
        }

        for index in self.tables.structures.iter() {
            match index {
                StructuresPartTablesIndex::Constants(index) => {
                    self.gen_constants(&mut out, index, enable_enum_transmute)?;
                }
                StructuresPartTablesIndex::Bits(index) => {
                    self.gen_bits(&mut out, index)?;
                }
                StructuresPartTablesIndex::Type(index) => {
                    self.gen_type(&mut out, index, enable_enum_transmute)?;
                }
                StructuresPartTablesIndex::Structure(index) => {
                    self.gen_structure(
                        &mut out,
                        index,
                        enable_enum_transmute,
                        enable_in_place_unmarshal,
                        enable_in_place_into_bufs_owner,
                    )?;
                }
                StructuresPartTablesIndex::Union(index) => {
                    self.gen_union(&mut out, index)?;
                }
                StructuresPartTablesIndex::Aliases(_index) => (),
            };
        }

        if gen_commands_macro {
            self.gen_commands_macro(&mut out)?;
        }

        Ok(())
    }
}
