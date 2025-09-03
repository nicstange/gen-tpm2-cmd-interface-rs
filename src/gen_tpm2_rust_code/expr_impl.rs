// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

use std::io::{self, Write};

use crate::tcg_tpm2::structures::expr::{
    Expr, ExprConstValue, ExprOp, ExprResolvedId, ExprResolvedType, ExprValue,
};
use crate::tcg_tpm2::structures::predefined::{PredefinedTypeRef, PredefinedTypes};
use crate::tcg_tpm2::structures::structure_table::{
    StructureTable, StructureTableEntryResolvedBaseType, StructureTableEntryType,
};
use crate::tcg_tpm2::structures::tables::{
    StructuresPartTablesConstantsIndex, StructuresPartTablesIndex,
};
use crate::tcg_tpm2::structures::union_table::{UnionTable, UnionTableEntryType};
use crate::tcg_tpm2::structures::value_range::ValueRange;

use super::{code_writer, Tpm2InterfaceRustCodeGenerator};

impl<'a> Tpm2InterfaceRustCodeGenerator<'a> {
    pub(super) fn predefined_type_to_rust(p: PredefinedTypeRef) -> &'static str {
        match p.bits {
            8 => match p.signed {
                true => "i8",
                false => "u8",
            },
            16 => match p.signed {
                true => "i16",
                false => "u16",
            },
            32 => match p.signed {
                true => "i32",
                false => "u32",
            },
            64 => match p.signed {
                true => "i64",
                false => "u64",
            },
            _ => unreachable!(),
        }
    }
    fn determine_plain_member_compiletime_max_size(
        &self,
        base_type: &StructureTableEntryResolvedBaseType,
    ) -> Option<i128> {
        match base_type {
            StructureTableEntryResolvedBaseType::Predefined(p) => Some(p.bits as i128 / 8),
            StructureTableEntryResolvedBaseType::Constants(index) => {
                let table = self.tables.structures.get_constants(*index);
                if let ExprValue::CompiletimeConstant(v) = table.size.as_ref().unwrap() {
                    Some(v.value)
                } else {
                    unreachable!()
                }
            }
            StructureTableEntryResolvedBaseType::Bits(index) => {
                let table = self.tables.structures.get_bits(*index);
                if let ExprValue::CompiletimeConstant(v) = table.size.as_ref().unwrap() {
                    Some(v.value)
                } else {
                    unreachable!()
                }
            }
            StructureTableEntryResolvedBaseType::Type(index) => {
                let table = self.tables.structures.get_type(*index);
                if let ExprValue::CompiletimeConstant(v) = table.size.as_ref().unwrap() {
                    Some(v.value)
                } else {
                    unreachable!()
                }
            }
            StructureTableEntryResolvedBaseType::Structure(index) => {
                let table = self.tables.structures.get_structure(*index);
                match table.max_size.as_ref().unwrap() {
                    ExprValue::CompiletimeConstant(v) => Some(v.value),
                    _ => None,
                }
            }
        }
    }

    fn determine_plain_member_max_size_type(
        &self,
        base_type: &StructureTableEntryResolvedBaseType,
    ) -> Result<PredefinedTypeRef, ()> {
        match base_type {
            StructureTableEntryResolvedBaseType::Structure(index) => {
                let table = self.tables.structures.get_structure(*index);
                self.determine_structure_max_size_type(&table)
            }
            _ => Ok(PredefinedTypes::find_type_with_repr(16, false).unwrap()),
        }
    }

    pub(super) fn determine_array_member_max_size_type(
        &self,
        array_max_size: &Expr,
        element_type: &StructureTableEntryResolvedBaseType,
    ) -> Result<PredefinedTypeRef, ()> {
        match array_max_size.value.as_ref().unwrap() {
            ExprValue::CompiletimeConstant(array_max_size) => {
                let element_max_size = match element_type {
                    StructureTableEntryResolvedBaseType::Predefined(p) => ExprConstValue {
                        value: (p.bits / 8) as i128,
                    },
                    StructureTableEntryResolvedBaseType::Constants(index) => {
                        let table = self.tables.structures.get_constants(*index);
                        match table.size.as_ref().unwrap() {
                            ExprValue::CompiletimeConstant(element_max_size) => *element_max_size,
                            _ => unreachable!(),
                        }
                    }
                    StructureTableEntryResolvedBaseType::Bits(index) => {
                        let table = self.tables.structures.get_bits(*index);
                        match table.size.as_ref().unwrap() {
                            ExprValue::CompiletimeConstant(element_max_size) => *element_max_size,
                            _ => unreachable!(),
                        }
                    }
                    StructureTableEntryResolvedBaseType::Type(index) => {
                        let table = self.tables.structures.get_type(*index);
                        match table.size.as_ref().unwrap() {
                            ExprValue::CompiletimeConstant(element_max_size) => *element_max_size,
                            _ => unreachable!(),
                        }
                    }
                    StructureTableEntryResolvedBaseType::Structure(index) => {
                        let table = self.tables.structures.get_structure(*index);
                        match table.max_size.as_ref().unwrap() {
                            ExprValue::CompiletimeConstant(element_max_size) => *element_max_size,
                            ExprValue::RuntimeConstant(_) => {
                                let size_type =
                                    PredefinedTypes::find_type_with_repr(32, false).unwrap();
                                let element_size_type =
                                    self.determine_structure_max_size_type(&table)?;
                                return PredefinedTypes::find_common_type(
                                    size_type,
                                    element_size_type,
                                )
                                .ok_or(());
                            }
                            _ => unreachable!(),
                        }
                    }
                };

                let max_size = array_max_size
                    .value
                    .checked_mul(element_max_size.value)
                    .ok_or(())?;
                let max_size = ExprConstValue { value: max_size };
                let repr_bits = max_size.repr_bits();
                let is_signed = max_size.is_signed();
                PredefinedTypes::find_type_for_value(16.max(repr_bits), is_signed).ok_or(())
            }
            ExprValue::RuntimeConstant(_) => {
                let size_type = PredefinedTypes::find_type_with_repr(32, false).unwrap();
                let member_size_type = self.determine_plain_member_max_size_type(element_type)?;
                PredefinedTypes::find_common_type(size_type, member_size_type).ok_or(())
            }
            _ => unreachable!(),
        }
    }

    pub(super) fn determine_structure_max_size_type(
        &self,
        table: &StructureTable,
    ) -> Result<PredefinedTypeRef, ()> {
        match table.max_size.as_ref().unwrap() {
            ExprValue::CompiletimeConstant(v) => {
                let repr_bits = v.repr_bits();
                let is_signed = v.is_signed();
                match PredefinedTypes::find_type_for_value(16.max(repr_bits), is_signed) {
                    Some(t) => Ok(t),
                    None => Err(()),
                }
            }
            ExprValue::RuntimeConstant(_) => {
                // Accumulate the total size of all members with sizes known at
                // compile-time each and determine a common size type for them
                // separately. This allows for the omission of a couple of
                // checked_add()s in the structure's generated
                // ::marshalled_max_size() implementation.
                let mut const_members_size: i128 = 0;
                let mut size_type = PredefinedTypes::find_type_with_repr(32, false).unwrap();
                for entry in &table.entries {
                    match &entry.entry_type {
                        StructureTableEntryType::Plain(plain_type) => {
                            let base_type = plain_type.resolved_base_type.as_ref().unwrap();
                            match self.determine_plain_member_compiletime_max_size(base_type) {
                                Some(member_size) => {
                                    const_members_size =
                                        const_members_size.checked_add(member_size).ok_or(())?;
                                }
                                None => {
                                    let member_size_type =
                                        self.determine_plain_member_max_size_type(base_type)?;
                                    size_type = PredefinedTypes::find_common_type(
                                        size_type,
                                        member_size_type,
                                    )
                                    .ok_or(())?;
                                }
                            };
                        }
                        StructureTableEntryType::Discriminant(discriminant) => {
                            let base_type =
                                discriminant.resolved_discriminant_type.as_ref().unwrap();
                            let base_type = StructureTableEntryResolvedBaseType::from(*base_type);
                            let member_size = self
                                .determine_plain_member_compiletime_max_size(&base_type)
                                .unwrap();
                            const_members_size =
                                const_members_size.checked_add(member_size).ok_or(())?;
                        }
                        StructureTableEntryType::Union(union_type) => {
                            let union_table_index =
                                union_type.resolved_union_type.as_ref().unwrap();
                            let union_table = self.tables.structures.get_union(*union_table_index);
                            match union_table.max_size.as_ref().unwrap() {
                                ExprValue::CompiletimeConstant(v) => {
                                    const_members_size =
                                        const_members_size.checked_add(v.value).ok_or(())?;
                                }
                                _ => {
                                    let member_size_type =
                                        self.determine_union_max_size_type(&union_table)?;
                                    size_type = PredefinedTypes::find_common_type(
                                        size_type,
                                        member_size_type,
                                    )
                                    .ok_or(())?;
                                }
                            };
                        }
                        StructureTableEntryType::Array(array_type) => {
                            let array_max_size = match &array_type.size_range {
                                Some(ValueRange::Range {
                                    min_value: _,
                                    max_value: Some(max_value),
                                }) => max_value,
                                _ => &array_type.size,
                            };
                            let element_type = array_type.resolved_element_type.as_ref().unwrap();
                            let is_compiletime_const = match array_max_size.value.as_ref().unwrap()
                            {
                                ExprValue::CompiletimeConstant(array_max_size) => {
                                    match self
                                        .determine_plain_member_compiletime_max_size(element_type)
                                    {
                                        Some(element_size) => {
                                            let member_size = array_max_size
                                                .value
                                                .checked_mul(element_size)
                                                .ok_or(())?;
                                            const_members_size = const_members_size
                                                .checked_add(member_size)
                                                .ok_or(())?;
                                            true
                                        }
                                        None => false,
                                    }
                                }
                                _ => false,
                            };

                            if !is_compiletime_const {
                                let member_size_type = self.determine_array_member_max_size_type(
                                    array_max_size,
                                    element_type,
                                )?;
                                size_type =
                                    PredefinedTypes::find_common_type(size_type, member_size_type)
                                        .ok_or(())?;
                            }
                        }
                    };
                }

                let const_members_size = ExprConstValue {
                    value: const_members_size,
                };
                let const_members_size_type = PredefinedTypes::find_type_for_value(
                    const_members_size.repr_bits(),
                    const_members_size.is_signed(),
                )
                .ok_or(())?;
                size_type = PredefinedTypes::find_common_type(size_type, const_members_size_type)
                    .ok_or(())?;
                Ok(size_type)
            }
            _ => unreachable!(),
        }
    }

    pub(super) fn determine_union_max_size_type(
        &self,
        table: &UnionTable,
    ) -> Result<PredefinedTypeRef, ()> {
        match table.max_size.as_ref().unwrap() {
            ExprValue::CompiletimeConstant(v) => {
                let repr_bits = v.repr_bits();
                let is_signed = v.is_signed();
                match PredefinedTypes::find_type_for_value(16.max(repr_bits), is_signed) {
                    Some(t) => Ok(t),
                    None => Err(()),
                }
            }
            ExprValue::RuntimeConstant(_) => {
                let mut size_type = PredefinedTypes::find_type_with_repr(32, false).unwrap();
                for entry in &table.entries {
                    match &entry.entry_type {
                        UnionTableEntryType::Plain(plain_type) => {
                            if plain_type.base_type.is_none() {
                                // No type means empty.
                                continue;
                            }
                            let base_type = plain_type.resolved_base_type.as_ref().unwrap();
                            let member_size_type =
                                self.determine_plain_member_max_size_type(base_type)?;
                            size_type =
                                PredefinedTypes::find_common_type(size_type, member_size_type)
                                    .ok_or(())?;
                        }
                        UnionTableEntryType::Array(array_type) => {
                            let element_type = array_type.resolved_element_type.as_ref().unwrap();
                            let member_size_type = self.determine_array_member_max_size_type(
                                &array_type.size,
                                element_type,
                            )?;
                            size_type =
                                PredefinedTypes::find_common_type(size_type, member_size_type)
                                    .ok_or(())?;
                        }
                    };
                }
                Ok(size_type)
            }
            _ => unreachable!(),
        }
    }

    pub(super) fn format_sizeof_ref(
        &self,
        t: &ExprResolvedType,
        target_type_hint: Option<PredefinedTypeRef>,
        limits_name: &str,
    ) -> Result<(String, PredefinedTypeRef, bool, bool), ()> {
        match t {
            ExprResolvedType::PredefinedType(p) => {
                let t = match target_type_hint {
                    Some(target_type_hint) => target_type_hint,
                    None => PredefinedTypes::find_type_with_repr(16, false).unwrap(),
                };
                Ok((
                    format!(
                        "mem::size_of::<{}>() as {}",
                        Self::predefined_type_to_rust(*p),
                        Self::predefined_type_to_rust(t)
                    ),
                    t,
                    false,
                    false,
                ))
            }
            ExprResolvedType::Type(index) => match index {
                StructuresPartTablesIndex::Constants(index) => {
                    let t = PredefinedTypes::find_type_with_repr(16, false).unwrap();
                    let table = self.tables.structures.get_constants(*index);
                    Ok((
                        Self::camelize(&table.name) + "::marshalled_size()",
                        t,
                        true,
                        false,
                    ))
                }
                StructuresPartTablesIndex::Bits(index) => {
                    let t = PredefinedTypes::find_type_with_repr(16, false).unwrap();
                    let table = self.tables.structures.get_bits(*index);
                    Ok((
                        Self::camelize(&table.name) + "::marshalled_size()",
                        t,
                        true,
                        false,
                    ))
                }
                StructuresPartTablesIndex::Type(index) => {
                    let t = PredefinedTypes::find_type_with_repr(16, false).unwrap();
                    let table = self.tables.structures.get_type(*index);
                    Ok((
                        Self::camelize(&table.name) + "::marshalled_size()",
                        t,
                        true,
                        false,
                    ))
                }
                StructuresPartTablesIndex::Structure(index) => {
                    let table = self.tables.structures.get_structure(*index);
                    let size_is_fixed = matches!(
                        table.size.as_ref().unwrap(),
                        ExprValue::CompiletimeConstant(_) | ExprValue::RuntimeConstant(_)
                    );
                    let max_size_method_name = if size_is_fixed {
                        "marshalled_size"
                    } else {
                        "marshalled_max_size"
                    };
                    let t = self.determine_structure_max_size_type(&table)?;
                    match table.max_size.as_ref().unwrap() {
                        ExprValue::CompiletimeConstant(_) => Ok((
                            table.name.to_ascii_lowercase() + "_" + max_size_method_name + "()",
                            t,
                            true,
                            false,
                        )),
                        ExprValue::RuntimeConstant(_) => Ok((
                            format!(
                                "{}_{}({})",
                                table.name.to_ascii_lowercase(),
                                max_size_method_name,
                                limits_name
                            ),
                            t,
                            true,
                            true,
                        )),
                        _ => unreachable!(),
                    }
                }
                StructuresPartTablesIndex::Union(index) => {
                    let table = self.tables.structures.get_union(*index);
                    let t = self.determine_union_max_size_type(&table)?;
                    match table.max_size.as_ref().unwrap() {
                        ExprValue::CompiletimeConstant(_) => Ok((
                            Self::camelize(&table.name) + "::marshalled_max_size()",
                            t,
                            true,
                            false,
                        )),
                        ExprValue::RuntimeConstant(_) => Ok((
                            format!(
                                "{}::marshalled_max_size({})",
                                Self::camelize(&table.name),
                                limits_name
                            ),
                            t,
                            true,
                            true,
                        )),
                        _ => unreachable!(),
                    }
                }
                StructuresPartTablesIndex::Aliases(_) => unreachable!(),
            },
        }
    }

    fn determine_sizeof_ref_min_type(&self, t: &ExprResolvedType) -> Result<PredefinedTypeRef, ()> {
        match t {
            ExprResolvedType::PredefinedType(_) => {
                Ok(PredefinedTypes::find_type_with_repr(16, false).unwrap())
            }
            ExprResolvedType::Type(index) => match index {
                StructuresPartTablesIndex::Constants(_) => {
                    Ok(PredefinedTypes::find_type_with_repr(16, false).unwrap())
                }
                StructuresPartTablesIndex::Bits(_) => {
                    Ok(PredefinedTypes::find_type_with_repr(16, false).unwrap())
                }
                StructuresPartTablesIndex::Type(_) => {
                    Ok(PredefinedTypes::find_type_with_repr(16, false).unwrap())
                }
                StructuresPartTablesIndex::Structure(index) => {
                    let table = self.tables.structures.get_structure(*index);
                    self.determine_structure_max_size_type(&table)
                }
                StructuresPartTablesIndex::Union(index) => {
                    let table = self.tables.structures.get_union(*index);
                    self.determine_union_max_size_type(&table)
                }
                StructuresPartTablesIndex::Aliases(_) => unreachable!(),
            },
        }
    }

    pub(super) fn format_compiletime_const_expr_cast(
        mut s: String,
        primitive: bool,
        target_type: PredefinedTypeRef,
    ) -> String {
        if !primitive {
            s = "(".to_owned() + &s;
            s += ")";
        }
        s += " as ";
        s += Self::predefined_type_to_rust(target_type);
        s
    }

    pub(super) fn format_compiletime_const_expr(
        &self,
        e: &Expr,
        target_type_hint: Option<PredefinedTypeRef>,
        limits_name: &str,
        context: Option<StructuresPartTablesIndex>,
    ) -> Result<(String, PredefinedTypeRef, bool), ()> {
        let value = if let ExprValue::CompiletimeConstant(value) = e.value.as_ref().unwrap() {
            value
        } else {
            unreachable!();
        };

        // In case a target type preference is specified, check that it fits the expression's value.
        let value_repr_bits = value.repr_bits();
        let value_is_signed = value.is_signed();
        let target_type_hint = target_type_hint.filter(|target_type_hint| {
            !(value_repr_bits > target_type_hint.bits
                || (value_repr_bits == target_type_hint.bits
                    && value_is_signed != target_type_hint.signed)
                || value.is_signed() && !target_type_hint.signed)
        });

        match &e.op {
            ExprOp::Hex(_) => {
                // If no preference on the target type, choose one for the value. Don't use types
                // less than 32 bits wide: if each primary expressions had the minimum type needed,
                // the expressions would quickly get cluttered by excessive casts to common types.
                let target_type = match target_type_hint {
                    Some(target_type_hint) => target_type_hint,
                    None => {
                        let repr_bits = 32.max(value.repr_bits());
                        let target_type =
                            PredefinedTypes::find_type_with_repr(repr_bits, value.is_signed());
                        match target_type {
                            Some(target_type) => target_type,
                            None => return Err(()),
                        }
                    }
                };
                let s = format!(
                    "{:#x}{}",
                    value.value,
                    Self::predefined_type_to_rust(target_type)
                );
                Ok((s, target_type, true))
            }
            ExprOp::Dec(_) => {
                // If no preference on the target type, choose one for the value. Don't use types
                // less than 32 bits wide: if each primary expressions had the minimum type needed,
                // the expressions would quickly get cluttered by excessive casts to common types.
                let target_type = match target_type_hint {
                    Some(target_type_hint) => target_type_hint,
                    None => {
                        let repr_bits = 32.max(value.repr_bits());
                        let target_type =
                            PredefinedTypes::find_type_with_repr(repr_bits, value.is_signed());
                        match target_type {
                            Some(target_type) => target_type,
                            None => return Err(()),
                        }
                    }
                };
                let s = format!(
                    "{}{}",
                    value.value,
                    Self::predefined_type_to_rust(target_type)
                );
                Ok((s, target_type, true))
            }
            ExprOp::Id(id) => {
                if let ExprResolvedId::Constant(id) = id.resolved.unwrap() {
                    let r = self.format_constant_ref(context, id, target_type_hint)?;
                    assert!(!r.2);
                    Ok((r.0, r.1, r.3))
                } else {
                    unreachable!();
                }
            }
            ExprOp::Sizeof(t) => {
                let r = self.format_sizeof_ref(
                    t.resolved.as_ref().unwrap(),
                    target_type_hint,
                    limits_name,
                )?;
                assert!(!r.3);
                Ok((r.0, r.1, r.2))
            }
            ExprOp::Add(e0, e1) => {
                let result_min_type =
                    match PredefinedTypes::find_type_for_value(value_repr_bits, value_is_signed) {
                        Some(result_min_type) => result_min_type,
                        None => return Err(()),
                    };
                let target_type_hint = match target_type_hint {
                    Some(target_type_hint) => target_type_hint,
                    None => {
                        if result_min_type.bits >= 32 {
                            result_min_type
                        } else {
                            PredefinedTypes::find_type_with_repr(32, value_is_signed).unwrap()
                        }
                    }
                };
                let target_type_hint = Some(target_type_hint);
                let (mut r0, t0, p0) =
                    self.format_compiletime_const_expr(e0, target_type_hint, limits_name, context)?;
                let (mut r1, t1, p1) =
                    self.format_compiletime_const_expr(e1, target_type_hint, limits_name, context)?;
                let common_type = match PredefinedTypes::find_common_type(t0, t1) {
                    Some(common_type) => common_type,
                    None => return Err(()),
                };
                let common_type =
                    match PredefinedTypes::find_common_type(common_type, result_min_type) {
                        Some(common_type) => common_type,
                        None => return Err(()),
                    };

                if t0 != common_type {
                    r0 = Self::format_compiletime_const_expr_cast(r0, p0, common_type);
                } else if let ExprOp::LShift(_, _) = &e0.op {
                    r0 = "(".to_owned() + &r0 + ")";
                }
                if t1 != common_type {
                    r1 = Self::format_compiletime_const_expr_cast(r1, p1, common_type);
                } else {
                    match &e1.op {
                        ExprOp::LShift(_, _) | ExprOp::Add(_, _) | ExprOp::Sub(_, _) => {
                            r1 = "(".to_owned() + &r1 + ")";
                        }
                        _ => (),
                    };
                }

                Ok((r0 + " + " + &r1, common_type, false))
            }
            ExprOp::Sub(e0, e1) => {
                let result_min_type =
                    match PredefinedTypes::find_type_for_value(value_repr_bits, value_is_signed) {
                        Some(result_min_type) => result_min_type,
                        None => return Err(()),
                    };
                let target_type_hint = match target_type_hint {
                    Some(target_type_hint) => target_type_hint,
                    None => {
                        if result_min_type.bits >= 32 {
                            result_min_type
                        } else {
                            PredefinedTypes::find_type_with_repr(32, value_is_signed).unwrap()
                        }
                    }
                };
                let target_type_hint = Some(target_type_hint);
                let (mut r0, t0, p0) =
                    self.format_compiletime_const_expr(e0, target_type_hint, limits_name, context)?;
                let (mut r1, t1, p1) =
                    self.format_compiletime_const_expr(e1, target_type_hint, limits_name, context)?;
                let common_type = match PredefinedTypes::find_common_type(t0, t1) {
                    Some(common_type) => common_type,
                    None => return Err(()),
                };
                let common_type =
                    match PredefinedTypes::find_common_type(common_type, result_min_type) {
                        Some(common_type) => common_type,
                        None => return Err(()),
                    };

                if t0 != common_type {
                    r0 = Self::format_compiletime_const_expr_cast(r0, p0, common_type);
                } else if let ExprOp::LShift(_, _) = &e0.op {
                    r0 = "(".to_owned() + &r0 + ")";
                }
                if t1 != common_type {
                    r1 = Self::format_compiletime_const_expr_cast(r1, p1, common_type);
                } else {
                    match &e1.op {
                        ExprOp::LShift(_, _) | ExprOp::Add(_, _) | ExprOp::Sub(_, _) => {
                            r1 = "(".to_owned() + &r1 + ")";
                        }
                        _ => (),
                    };
                }

                Ok((r0 + " - " + &r1, common_type, false))
            }
            ExprOp::Mul(e0, e1) => {
                let result_min_type =
                    match PredefinedTypes::find_type_for_value(value_repr_bits, value_is_signed) {
                        Some(result_min_type) => result_min_type,
                        None => return Err(()),
                    };
                let target_type_hint = match target_type_hint {
                    Some(target_type_hint) => target_type_hint,
                    None => {
                        if result_min_type.bits >= 32 {
                            result_min_type
                        } else {
                            PredefinedTypes::find_type_with_repr(32, value_is_signed).unwrap()
                        }
                    }
                };
                let target_type_hint = Some(target_type_hint);
                let (mut r0, t0, p0) =
                    self.format_compiletime_const_expr(e0, target_type_hint, limits_name, context)?;
                let (mut r1, t1, p1) =
                    self.format_compiletime_const_expr(e1, target_type_hint, limits_name, context)?;
                let common_type = match PredefinedTypes::find_common_type(t0, t1) {
                    Some(common_type) => common_type,
                    None => return Err(()),
                };
                let common_type =
                    match PredefinedTypes::find_common_type(common_type, result_min_type) {
                        Some(common_type) => common_type,
                        None => return Err(()),
                    };

                if t0 != common_type {
                    r0 = Self::format_compiletime_const_expr_cast(r0, p0, common_type);
                } else {
                    match &e0.op {
                        ExprOp::LShift(_, _) | ExprOp::Add(_, _) | ExprOp::Sub(_, _) => {
                            r0 = "(".to_owned() + &r0 + ")";
                        }
                        _ => (),
                    };
                }
                if t1 != common_type {
                    r1 = Self::format_compiletime_const_expr_cast(r1, p1, common_type);
                } else {
                    match &e1.op {
                        ExprOp::LShift(_, _)
                        | ExprOp::Add(_, _)
                        | ExprOp::Sub(_, _)
                        | ExprOp::Mul(_, _) => {
                            r1 = "(".to_owned() + &r1 + ")";
                        }
                        _ => (),
                    };
                }

                Ok((r0 + " * " + &r1, common_type, false))
            }
            ExprOp::LShift(e0, e1) => {
                let value_repr_bits = if value_repr_bits == 0u32 {
                    // The shifted value is zero. Make the operand's type
                    // huge enough gfor the shift, because otherwise the code
                    // won't compile.
                    match e1.value.as_ref().unwrap() {
                        ExprValue::CompiletimeConstant(v1) => {
                            let v1 = v1.value;
                            if v1 < 0i128 || v1 > (u32::MAX - 1) as i128 {
                                return Err(());
                            }
                            v1 as u32 + 1u32
                        }
                        _ => unreachable!(),
                    }
                } else {
                    value_repr_bits
                };
                let result_min_type =
                    match PredefinedTypes::find_type_for_value(value_repr_bits, value_is_signed) {
                        Some(result_min_type) => result_min_type,
                        None => return Err(()),
                    };
                let target_type_hint = match target_type_hint {
                    Some(target_type_hint) => target_type_hint,
                    None => {
                        if result_min_type.bits >= 32 {
                            result_min_type
                        } else {
                            PredefinedTypes::find_type_with_repr(32, value_is_signed).unwrap()
                        }
                    }
                };
                let target_type_hint = Some(target_type_hint);
                let (mut r0, t0, p0) =
                    self.format_compiletime_const_expr(e0, target_type_hint, limits_name, context)?;
                let (mut r1, _t1, _) =
                    self.format_compiletime_const_expr(e1, None, limits_name, context)?;
                let common_type = match PredefinedTypes::find_common_type(t0, result_min_type) {
                    Some(common_type) => common_type,
                    None => return Err(()),
                };
                if t0 != common_type {
                    r0 = Self::format_compiletime_const_expr_cast(r0, p0, common_type);
                    r0 = "(".to_owned() + &r0 + ")";
                }

                if let ExprOp::LShift(_, _) = &e1.op {
                    r1 = "(".to_owned() + &r1 + ")";
                }

                Ok((r0 + " << " + &r1, common_type, false))
            }
        }
    }

    pub(super) fn format_compiletime_const_expr_for_type(
        &self,
        e: &Expr,
        target_type: PredefinedTypeRef,
        limits_name: &str,
        context: Option<StructuresPartTablesIndex>,
    ) -> Result<(String, bool), ()> {
        // First check if the constant value is overflowing the specified target_type.
        let value = if let ExprValue::CompiletimeConstant(value) = e.value.as_ref().unwrap() {
            value
        } else {
            unreachable!();
        };
        let value_repr_bits = value.repr_bits();
        let value_is_signed = value.is_signed();
        if value_repr_bits > target_type.bits
            || (value_repr_bits == target_type.bits && value_is_signed != target_type.signed)
            || (value.is_signed() && !target_type.signed)
        {
            return Err(());
        }

        let (mut s, t, mut p) =
            self.format_compiletime_const_expr(e, Some(target_type), limits_name, context)?;
        if t != target_type {
            s = Self::format_compiletime_const_expr_cast(s, p, target_type);
            p = false;
        }
        Ok((s, p))
    }

    pub(super) fn determine_compiletime_const_expr_min_type(
        &self,
        e: &Expr,
    ) -> Result<PredefinedTypeRef, ()> {
        let value = if let ExprValue::CompiletimeConstant(value) = e.value.as_ref().unwrap() {
            value
        } else {
            unreachable!();
        };

        match PredefinedTypes::find_type_for_value(value.repr_bits(), value.is_signed()) {
            Some(target_type) => Ok(target_type),
            None => Err(()),
        }
    }

    fn format_expr_cast<W: io::Write, HE>(
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
        mut s: String,
        primitive: bool,
        target_type: PredefinedTypeRef,
        source_type: PredefinedTypeRef,
        e: &Expr,
        handle_err: &HE,
    ) -> Result<String, io::Error>
    where
        HE: Fn(&mut code_writer::IndentedCodeWriter<'_, W>) -> Result<(), io::Error>,
    {
        if source_type != target_type {
            if source_type.bits > target_type.bits
                || (!source_type.signed
                    && target_type.signed
                    && source_type.bits == target_type.bits)
                || source_type.signed && !target_type.signed
            {
                // Non-trivial cast that needs checking.
                if let ExprValue::CompiletimeConstant(value) = e.value.as_ref().unwrap() {
                    let value_repr_bits = value.repr_bits();
                    let value_is_signed = value.is_signed();
                    if value_repr_bits > target_type.bits
                        || (value_repr_bits == target_type.bits
                            && value_is_signed != target_type.signed)
                        || (value.is_signed() && !target_type.signed)
                    {
                        return Err(io::Error::from(io::ErrorKind::InvalidData));
                    }
                    return Ok(Self::format_compiletime_const_expr_cast(
                        s,
                        primitive,
                        target_type,
                    ));
                }

                if source_type.signed && !target_type.signed {
                    if source_type.bits > target_type.bits {
                        writeln!(
                            out,
                            "if {} < 0 || {} > {}::MAX as {} {{",
                            &s,
                            &s,
                            Self::predefined_type_to_rust(target_type),
                            Self::predefined_type_to_rust(source_type)
                        )?;
                    } else {
                        writeln!(out, "if {} < 0 {{", &s)?;
                    }
                    let mut iout = out.make_indent();
                    handle_err(&mut iout)?;
                    writeln!(out, "}}")?;
                } else {
                    assert!(
                        source_type.bits > target_type.bits
                            || (!source_type.signed
                                && target_type.signed
                                && source_type.bits == target_type.bits)
                    );
                    writeln!(
                        out,
                        "if {} > {}::MAX as {} {{",
                        &s,
                        Self::predefined_type_to_rust(target_type),
                        Self::predefined_type_to_rust(source_type)
                    )?;
                    let mut iout = out.make_indent();
                    handle_err(&mut iout)?;
                    writeln!(out, "}}")?;
                }

                if !primitive {
                    s = "(".to_owned() + &s;
                    s += ")";
                }
                s = s + " as " + Self::predefined_type_to_rust(target_type);
            } else {
                match &e.value.as_ref().unwrap() {
                    ExprValue::CompiletimeConstant(_) => {
                        s = Self::format_compiletime_const_expr_cast(s, primitive, target_type);
                    }
                    _ => {
                        if !primitive {
                            s = "(".to_owned() + &s;
                            s += ")";
                        }
                        s = s + " as " + Self::predefined_type_to_rust(target_type);
                    }
                };
            }
        }
        Ok(s)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn format_expr<W: io::Write, FI, HE>(
        &self,
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
        e: &Expr,
        target_type_hint: Option<PredefinedTypeRef>,
        limits_name: &str,
        context: Option<StructuresPartTablesIndex>,
        format_local_id_ref: &FI,
        handle_err: &HE,
    ) -> Result<(String, PredefinedTypeRef, bool), io::Error>
    where
        FI: Fn(usize, Option<PredefinedTypeRef>) -> Result<(String, PredefinedTypeRef, bool), ()>,
        HE: Fn(&mut code_writer::IndentedCodeWriter<'_, W>) -> Result<(), io::Error>,
    {
        if let ExprValue::CompiletimeConstant(_) = e.value.as_ref().unwrap() {
            return self
                .format_compiletime_const_expr(e, target_type_hint, limits_name, context)
                .map_err(|_| io::Error::from(io::ErrorKind::InvalidData));
        }

        match &e.op {
            ExprOp::Hex(_) | ExprOp::Dec(_) => unreachable!(),
            ExprOp::Id(id) => {
                let (r, t, can_fail, primitive) = match id.resolved.as_ref().unwrap() {
                    ExprResolvedId::Constant(i) => {
                        self.format_constant_ref(context, *i, target_type_hint)
                    }
                    ExprResolvedId::PredefinedConstant(p) => {
                        let t = PredefinedTypes::lookup(p.value_type).unwrap();
                        let (can_fail, fun_call_parens) = if !p.is_primary() {
                            (true, "()")
                        } else {
                            (false, "")
                        };
                        Ok((
                            format!(
                                "{}.{}{}",
                                limits_name,
                                p.name.to_ascii_lowercase(),
                                fun_call_parens
                            ),
                            t,
                            can_fail,
                            true,
                        ))
                    }
                    ExprResolvedId::StructMember(j) => {
                        format_local_id_ref(*j, target_type_hint).map(|r| (r.0, r.1, r.2, true))
                    }
                }
                .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;

                if !can_fail {
                    Ok((r, t, primitive))
                } else {
                    writeln!(out, "let v{} = match {} {{", e.rdepth, r)?;
                    let mut iout = out.make_indent();
                    writeln!(iout, "Ok(v) => v,")?;
                    writeln!(&mut iout, "Err(_) => {{")?;
                    let mut iiout = iout.make_indent();
                    writeln!(
                        &mut iiout,
                        "debug_assert!(false, \"Unexpected runtime constant evaluation failure\");"
                    )?;
                    handle_err(&mut iiout)?;
                    writeln!(&mut iout, "}},")?;
                    writeln!(out, "}};")?;
                    Ok(("v".to_owned() + &e.rdepth.to_string(), t, true))
                }
            }
            ExprOp::Sizeof(t) => {
                let (r, t, p, can_fail) = self
                    .format_sizeof_ref(t.resolved.as_ref().unwrap(), target_type_hint, limits_name)
                    .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;

                if !can_fail {
                    Ok((r, t, p))
                } else {
                    writeln!(out, "let v{} = match {} {{", e.rdepth, r)?;
                    let mut iout = out.make_indent();
                    writeln!(iout, "Ok(v) => v,")?;
                    writeln!(&mut iout, "Err(_) => {{")?;
                    let mut iiout = iout.make_indent();
                    writeln!(
                        &mut iiout,
                        "debug_assert!(false, \"Unexpected sizeof() evaluation failure\");"
                    )?;
                    handle_err(&mut iiout)?;
                    writeln!(&mut iout, "}},")?;
                    writeln!(out, "}};")?;
                    Ok(("v".to_owned() + &e.rdepth.to_string(), t, true))
                }
            }
            ExprOp::Add(e0, e1) => {
                let (mut r0, t0, mut p0) = self.format_expr(
                    out,
                    e0,
                    target_type_hint,
                    limits_name,
                    context,
                    format_local_id_ref,
                    handle_err,
                )?;
                let (mut r1, t1, p1) = self.format_expr(
                    out,
                    e1,
                    target_type_hint,
                    limits_name,
                    context,
                    format_local_id_ref,
                    handle_err,
                )?;

                let target_type = match PredefinedTypes::find_common_type(t0, t1) {
                    Some(target_type) => target_type,
                    None => {
                        return Err(io::Error::from(io::ErrorKind::InvalidData));
                    }
                };
                let target_type = match target_type_hint {
                    Some(hint) => {
                        // Consider the type hint only if it's wide enough to hold
                        // the result.
                        match PredefinedTypes::find_common_type(target_type, hint) {
                            Some(t) => {
                                if t == hint {
                                    hint
                                } else {
                                    target_type
                                }
                            }
                            None => target_type,
                        }
                    }
                    None => {
                        if target_type.bits < 32 {
                            PredefinedTypes::find_type_with_repr(32, target_type.signed).unwrap()
                        } else {
                            target_type
                        }
                    }
                };

                if t0 != target_type {
                    r0 = Self::format_expr_cast(out, r0, p0, target_type, t0, e0, handle_err)?;
                    p0 = false;
                }

                if !p0 {
                    r0 = "(".to_owned() + &r0 + ")";
                }

                if t1 != target_type {
                    r1 = Self::format_expr_cast(out, r1, p1, target_type, t1, e1, handle_err)?;
                }

                writeln!(
                    out,
                    "let v{} = match {}.checked_add({}) {{",
                    e.rdepth, r0, r1
                )?;
                let mut iout = out.make_indent();
                writeln!(&mut iout, "Some(v) => v,")?;
                writeln!(&mut iout, "None => {{")?;
                let mut iiout = iout.make_indent();
                handle_err(&mut iiout)?;
                writeln!(&mut iout, "}},")?;
                writeln!(out, "}};")?;

                Ok(("v".to_owned() + &e.rdepth.to_string(), target_type, true))
            }
            ExprOp::Sub(e0, e1) => {
                let (mut r0, t0, mut p0) = self.format_expr(
                    out,
                    e0,
                    target_type_hint,
                    limits_name,
                    context,
                    format_local_id_ref,
                    handle_err,
                )?;
                let (mut r1, t1, p1) = self.format_expr(
                    out,
                    e1,
                    target_type_hint,
                    limits_name,
                    context,
                    format_local_id_ref,
                    handle_err,
                )?;

                let target_type = match PredefinedTypes::find_common_type(t0, t1) {
                    Some(target_type) => target_type,
                    None => {
                        return Err(io::Error::from(io::ErrorKind::InvalidData));
                    }
                };
                let target_type = match target_type_hint {
                    Some(hint) => {
                        // Consider the type hint only if it's wide enough to hold
                        // the result.
                        match PredefinedTypes::find_common_type(target_type, hint) {
                            Some(t) => {
                                if t == hint {
                                    hint
                                } else {
                                    target_type
                                }
                            }
                            None => target_type,
                        }
                    }
                    None => {
                        if target_type.bits < 32 {
                            PredefinedTypes::find_type_with_repr(32, target_type.signed).unwrap()
                        } else {
                            target_type
                        }
                    }
                };

                if t0 != target_type {
                    r0 = Self::format_expr_cast(out, r0, p0, target_type, t0, e0, handle_err)?;
                    p0 = false;
                }

                if !p0 {
                    r0 = "(".to_owned() + &r0 + ")";
                }

                if t1 != target_type {
                    r1 = Self::format_expr_cast(out, r1, p1, target_type, t1, e1, handle_err)?;
                }

                writeln!(
                    out,
                    "let v{} = match {}.checked_sub({}) {{",
                    e.rdepth, r0, r1
                )?;
                let mut iout = out.make_indent();
                writeln!(&mut iout, "Some(v) => v,")?;
                writeln!(&mut iout, "None => {{")?;
                let mut iiout = iout.make_indent();
                handle_err(&mut iiout)?;
                writeln!(&mut iout, "}},")?;
                writeln!(out, "}};")?;

                Ok(("v".to_owned() + &e.rdepth.to_string(), target_type, true))
            }
            ExprOp::Mul(e0, e1) => {
                let (mut r0, t0, mut p0) = self.format_expr(
                    out,
                    e0,
                    target_type_hint,
                    limits_name,
                    context,
                    format_local_id_ref,
                    handle_err,
                )?;
                let (mut r1, t1, p1) = self.format_expr(
                    out,
                    e1,
                    target_type_hint,
                    limits_name,
                    context,
                    format_local_id_ref,
                    handle_err,
                )?;

                let target_type = match PredefinedTypes::find_common_type(t0, t1) {
                    Some(target_type) => target_type,
                    None => {
                        return Err(io::Error::from(io::ErrorKind::InvalidData));
                    }
                };
                let target_type = match target_type_hint {
                    Some(hint) => {
                        // Consider the type hint only if it's wide enough to hold
                        // the result.
                        match PredefinedTypes::find_common_type(target_type, hint) {
                            Some(t) => {
                                if t == hint {
                                    hint
                                } else {
                                    target_type
                                }
                            }
                            None => target_type,
                        }
                    }
                    None => {
                        if target_type.bits < 32 {
                            PredefinedTypes::find_type_with_repr(32, target_type.signed).unwrap()
                        } else {
                            target_type
                        }
                    }
                };

                if t0 != target_type {
                    r0 = Self::format_expr_cast(out, r0, p0, target_type, t0, e0, handle_err)?;
                    p0 = false;
                }

                if !p0 {
                    r0 = "(".to_owned() + &r0 + ")";
                }

                if t1 != target_type {
                    r1 = Self::format_expr_cast(out, r1, p1, target_type, t1, e1, handle_err)?;
                }

                writeln!(
                    out,
                    "let v{} = match {}.checked_mul({}) {{",
                    e.rdepth, r0, r1
                )?;
                let mut iout = out.make_indent();
                writeln!(&mut iout, "Some(v) => v,")?;
                writeln!(&mut iout, "None => {{")?;
                let mut iiout = iout.make_indent();
                handle_err(&mut iiout)?;
                writeln!(&mut iout, "}},")?;
                writeln!(out, "}};")?;

                Ok(("v".to_owned() + &e.rdepth.to_string(), target_type, true))
            }
            ExprOp::LShift(e0, e1) => {
                let (mut r0, t0, mut p0) = self.format_expr(
                    out,
                    e0,
                    target_type_hint,
                    limits_name,
                    context,
                    format_local_id_ref,
                    handle_err,
                )?;
                let distance_type = PredefinedTypes::find_type_with_repr(32, false).unwrap();
                let (mut r1, t1, p1) = self.format_expr(
                    out,
                    e1,
                    Some(distance_type),
                    limits_name,
                    context,
                    format_local_id_ref,
                    handle_err,
                )?;

                let target_type = t0;
                let target_type = match target_type_hint {
                    Some(hint) => {
                        // Consider the type hint only if it's wide enough to hold
                        // the result.
                        match PredefinedTypes::find_common_type(target_type, hint) {
                            Some(t) => {
                                if t == hint {
                                    hint
                                } else {
                                    target_type
                                }
                            }
                            None => target_type,
                        }
                    }
                    None => {
                        if target_type.bits < 32 {
                            PredefinedTypes::find_type_with_repr(32, target_type.signed).unwrap()
                        } else {
                            target_type
                        }
                    }
                };

                if t0 != target_type {
                    r0 = Self::format_expr_cast(out, r0, p0, target_type, t0, e0, handle_err)?;
                    p0 = false;
                }

                if t1 != distance_type {
                    r1 = Self::format_expr_cast(out, r1, p1, distance_type, t1, e1, handle_err)?;
                }

                if !target_type.signed {
                    if !p0 {
                        r0 = "(".to_owned() + &r0 + ")";
                    }
                } else {
                    writeln!(out, "let v{} = {};", e0.rdepth, r0)?;
                    r0 = "v".to_owned() + &e0.rdepth.to_string();
                    writeln!(out, "let v{} = {};", e1.rdepth, r1)?;
                    r1 = "v".to_owned() + &e1.rdepth.to_string();
                    writeln!(
                        out,
                        "if {} >= {} || {} < 0 || {} > {}::MAX >> {} {{",
                        &r1,
                        target_type.bits,
                        &r0,
                        &r0,
                        Self::predefined_type_to_rust(target_type),
                        &r1
                    )?;
                    let mut iout = out.make_indent();
                    handle_err(&mut iout)?;
                    writeln!(out, "}}")?;
                }

                writeln!(
                    out,
                    "let v{} = match {}.checked_shl({}) {{",
                    e.rdepth, r0, r1
                )?;
                let mut iout = out.make_indent();
                writeln!(&mut iout, "Some(v) => v,")?;
                writeln!(&mut iout, "None => {{")?;
                let mut iiout = iout.make_indent();
                handle_err(&mut iiout)?;
                writeln!(&mut iout, "}},")?;
                writeln!(out, "}};")?;

                Ok(("v".to_owned() + &e.rdepth.to_string(), target_type, true))
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn format_expr_for_type<W: io::Write, FI, HE>(
        &self,
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
        e: &Expr,
        target_type: PredefinedTypeRef,
        limits_name: &str,
        context: Option<StructuresPartTablesIndex>,
        format_local_id_ref: &FI,
        handle_err: &HE,
    ) -> Result<String, io::Error>
    where
        FI: Fn(usize, Option<PredefinedTypeRef>) -> Result<(String, PredefinedTypeRef, bool), ()>,
        HE: Fn(&mut code_writer::IndentedCodeWriter<'_, W>) -> Result<(), io::Error>,
    {
        let (mut r, t, p) = self.format_expr(
            out,
            e,
            Some(target_type),
            limits_name,
            context,
            format_local_id_ref,
            handle_err,
        )?;
        if t != target_type {
            r = Self::format_expr_cast(out, r, p, target_type, t, e, handle_err)?;
        }
        Ok(r)
    }

    pub(super) fn determine_expr_min_type<FI>(
        &self,
        e: &Expr,
        format_local_id_ref: &mut FI,
    ) -> Result<PredefinedTypeRef, ()>
    where
        FI: FnMut(
            usize,
            Option<PredefinedTypeRef>,
        ) -> Result<(String, PredefinedTypeRef, bool), ()>,
    {
        if let ExprValue::CompiletimeConstant(_) = e.value.as_ref().unwrap() {
            return self.determine_compiletime_const_expr_min_type(e);
        }

        match &e.op {
            ExprOp::Hex(_) | ExprOp::Dec(_) => unreachable!(),
            ExprOp::Id(id) => match id.resolved.as_ref().unwrap() {
                ExprResolvedId::Constant(i) => {
                    let t = self
                        .tables
                        .structures
                        .get_constants(StructuresPartTablesConstantsIndex::from(*i));
                    if let Some(base_type) = t.resolved_base {
                        return Ok(base_type);
                    }

                    let c = &self.tables.structures.get_constant(*i).value;
                    self.determine_expr_min_type(c, format_local_id_ref)
                }
                ExprResolvedId::PredefinedConstant(p) => {
                    Ok(PredefinedTypes::lookup(p.value_type).unwrap())
                }
                ExprResolvedId::StructMember(j) => format_local_id_ref(*j, None).map(|r| r.1),
            },
            ExprOp::Sizeof(t) => self.determine_sizeof_ref_min_type(t.resolved.as_ref().unwrap()),
            ExprOp::Add(e0, e1) | ExprOp::Sub(e0, e1) | ExprOp::Mul(e0, e1) => {
                let t0 = self.determine_expr_min_type(e0, format_local_id_ref)?;
                let t1 = self.determine_expr_min_type(e1, format_local_id_ref)?;
                match PredefinedTypes::find_common_type(t0, t1) {
                    Some(target_type) => Ok(target_type),
                    None => Err(()),
                }
            }
            ExprOp::LShift(e0, _e1) => self.determine_expr_min_type(e0, format_local_id_ref),
        }
    }
}
