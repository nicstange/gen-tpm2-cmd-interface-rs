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
        enable_panic_free: bool,
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

extern crate allocator_api2;
use allocator_api2::{{alloc, boxed, vec}};

use alloc::Allocator;
use vec::Vec;
use boxed::Box;
use core::cmp;
use core::convert;
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
",
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION")
        )?;

        if !enable_panic_free {
            write!(
                &mut out,
                "
fn copy_vec_from_slice<T: Copy, A: Allocator>(slice: &[T], alloc: A) -> Result<Vec<T, A>, TpmErr> {{
    let mut v = Vec::new_in(alloc);
    v.try_reserve_exact(slice.len()).map_err(|_| TpmErr::Rc(TpmRc::MEMORY))?;
    v.extend_from_slice(slice);
    Ok(v)
}}
"
            )?;
        } else {
            write!(
                &mut out,
                "
fn copy_vec_from_slice<T: Copy, A: Allocator>(slice: &[T], alloc: A) -> Result<Vec<T, A>, TpmErr> {{
    let mut v = Vec::new_in(alloc);
    v.try_reserve_exact(slice.len()).map_err(|_| TpmErr::Rc(TpmRc::MEMORY))?;
    unsafe {{ ptr::copy_nonoverlapping(slice.as_ptr(), v.as_mut_ptr(), slice.len()) }};
    unsafe {{ v.set_len(slice.len()) }};
    Ok(v)
}}
"
            )?;
        }

        write!(
            &mut out,
            "
#[derive(Clone, Debug)]
pub enum TpmBuffer<'a, A: Allocator> {{
    Borrowed(&'a [u8]),
    Owned(Vec<u8, A>),
}}

impl<'a, A: Allocator> TpmBuffer<'a, A> {{
    pub fn into_owned(mut self, alloc: A) -> Result<TpmBuffer<'static, A>, TpmErr> {{
        let o = match &mut self {{
            Self::Borrowed(b) => copy_vec_from_slice(b, alloc)?,
            Self::Owned(o) => mem::replace(o, Vec::new_in(alloc)),
        }};
        Ok(TpmBuffer::<'static, A>::Owned(o))
    }}
}}

#[cfg(zeroize)]
impl<'a, A: Allocator> Drop for TpmBuffer<'a, A> {{
    fn drop(&mut self) {{
        match self {{
            Self::Borrowed(_) => (),
            Self::Owned(o) => {{
                <&mut [u8] as zeroize::Zeroize>::zeroize(o.deref_mut());
            }}
        }}
    }}
}}

impl<'a, A: Allocator> ops::Deref for TpmBuffer<'a, A> {{
    type Target = [u8];

    fn deref(&self) -> &Self::Target {{
        match self {{
            Self::Borrowed(b) => b,
            Self::Owned(o) => &o,
        }}
    }}
}}

impl<'a, A: Allocator> convert::From<&'a [u8]> for TpmBuffer<'a, A> {{
    fn from(value: &'a [u8]) -> Self {{
        Self::Borrowed(value)
    }}
}}

impl<'a, A: Allocator> PartialEq for TpmBuffer<'a, A> {{
    fn eq(&self, other: &Self) -> bool {{
        <Self as ops::Deref>::deref(self) == <Self as ops::Deref>::deref(other)
    }}
}}
"
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
        if !enable_panic_free {
            writeln!(&mut iout, "Ok(s.split_at(mid))")?;
        } else {
            writeln!(&mut iout, "Ok(unsafe {{ s.split_at_unchecked(mid) }})")?;
        }
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
        if !enable_panic_free {
            writeln!(&mut iout, "Ok(s.split_at_mut(mid))")?;
        } else {
            writeln!(&mut iout, "Ok(unsafe {{ s.split_at_mut_unchecked(mid) }})")?;
        }
        writeln!(&mut out, "}}")?;

        for b in [8, 16, 32, 64] {
            for s in ['u', 'i'] {
                let t = format!("{}{}", s, b);
                writeln!(&mut out)?;
                writeln!(&mut out,"pub fn unmarshal_{}(buf: &[u8]) -> Result<(&[u8], {}), TpmErr> {{",
                         &t, &t)?;
                let mut iout = out.make_indent();
                writeln!(&mut iout, "let (consumed, buf) = split_slice_at(buf, mem::size_of::<{}>())?;", &t)?;
                if enable_unaligned_accesses {
                    writeln!(&mut iout, "let p = consumed.as_ptr() as *const {};", &t)?;
                    writeln!(&mut iout, "let value = unsafe{{p.read_unaligned()}};")?;
                    writeln!(&mut iout, "let value = {}::from_be(value);", &t)?;
                } else {
                    writeln!(
                        &mut iout,
                        "let consumed = <&[u8; mem::size_of::<{}>()]>::try_from(consumed).map_err(|_| TpmErr::InternalErr)?;",
                        &t
                    )?;
                    writeln!(&mut iout, "let value = {}::from_be_bytes(*consumed);", &t)?;
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
                    "pub fn marshal_{}<'a>(buf: &mut [u8], value: {}) -> Result<&mut [u8], TpmErr> {{",
                    &t, &t
                )?;
                let mut iout = out.make_indent();
                writeln!(
                    &mut iout,
                    "let (produced, buf) = split_slice_at_mut(buf, mem::size_of::<{}>())?;",
                    &t
                )?;
                if enable_unaligned_accesses {
                    writeln!(&mut iout, "let value = {}::to_be(value);", &t)?;
                    writeln!(&mut iout, "let p = produced.as_mut_ptr() as *mut {};", &t)?;
                    writeln!(&mut iout, "unsafe{{p.write_unaligned(value)}};")?;
                } else {
                    writeln!(
                        &mut iout,
                        "let produced = <&mut [u8; mem::size_of::<{}>()]>::try_from(produced).map_err(|_| TpmErr::InternalErr)?;",
                        &t
                    )?;
                    writeln!(&mut iout, "*produced = value.to_be_bytes();")?;
                }
                writeln!(&mut iout, "Ok(buf)")?;
                writeln!(&mut out, "}}")?;
            }
        }

        if !enable_panic_free {
            write!(
                &mut out,
                "
fn marshal_bytes<'a>(buf: &'a mut [u8], src: &[u8]) -> Result<&'a mut [u8], TpmErr> {{
    let (produced, buf) = split_slice_at_mut(buf, src.len())?;
    produced.copy_from_slice(src);
    Ok(buf)
}}
"
            )?;
        } else {
            write!(
                &mut out,
                "
fn marshal_bytes<'a>(buf: &'a mut [u8], src: &[u8]) -> Result<&'a mut [u8], TpmErr> {{
    let (produced, buf) = split_slice_at_mut(buf, src.len())?;
    unsafe {{ ptr::copy_nonoverlapping(src.as_ptr(), produced.as_mut_ptr(), src.len()) }};
    Ok(buf)
}}
"
            )?;
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
