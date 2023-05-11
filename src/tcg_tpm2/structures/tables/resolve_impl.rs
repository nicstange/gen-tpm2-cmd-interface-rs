// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

use std::cell::RefMut;
use std::cmp;
use std::io;

use super::super::bits_table::BitsTableResolvedBase;
use super::super::deps::ConfigDeps;
use super::super::expr::{Expr, ExprOp, ExprParser, ExprResolvedId, ExprResolvedType};
use super::super::predefined::{PredefinedConstants, PredefinedTypes};
use super::super::structure_table::{
    StructureTableEntry, StructureTableEntryDiscriminantType, StructureTableEntryResolvedBaseType,
    StructureTableEntryType,
};
use super::super::type_table::{TypeTableEntry, TypeTableResolvedBase};
use super::super::union_table::{UnionTableEntryResolvedBaseType, UnionTableEntryType};
use super::super::value_range::ValueRange;

use super::{
    StructuresPartTables, StructuresPartTablesAliasesIndex, StructuresPartTablesConstantsIndex,
    StructuresPartTablesIndex, StructuresPartTablesStructureIndex, StructuresPartTablesUnionIndex,
};

impl StructuresPartTables {
    fn cpp_expand_expr_ids(&self, item_name: &str, e: &mut Expr) -> Result<(), io::Error> {
        e.transform_in_place(&mut |e: &mut Expr, r: &[Result<(), io::ErrorKind>]| {
            match &e.op {
                ExprOp::Id(id) => {
                    if let Some(replacement) = self.lookup_cppdefine(&id.name) {
                        let repl = ExprParser::parse(replacement);
                        match repl {
                            Ok(repl) => {
                                *e = repl;
                                Ok(())
                            },
                            Err(_) => {
                                eprintln!("error: {}: failed to parse expression from \"{}\" CPP-style define",
                                          item_name, &id.name);
                                Err(io::ErrorKind::InvalidData)
                            }
                        }
                    } else {
                        Ok(())
                    }
                },
                ExprOp::Hex(_) |
                ExprOp::Dec(_) |
                ExprOp::Sizeof(_) => Ok(()),
                ExprOp::Add(_, _) |
                ExprOp::Sub(_, _) |
                ExprOp::Mul(_, _) |
                ExprOp::LShift(_, _) => {
                    if r[0].is_err() {
                        r[0]
                    } else {
                        r[1]
                    }
                },
            }
        }).map_err(io::Error::from)
    }

    fn resolve_expr_id(
        &self,
        item_name: &str,
        id: &str,
        locals: Option<&[StructureTableEntry]>,
    ) -> Result<ExprResolvedId, io::ErrorKind> {
        if let Some(locals) = locals {
            for (i, l) in locals.iter().enumerate() {
                if l.name == id {
                    return Ok(ExprResolvedId::StructMember(i));
                }
            }
        }
        if let Some(c) = self.lookup_constant(id) {
            Ok(ExprResolvedId::Constant(c))
        } else if let Some(p) = PredefinedConstants::lookup(id) {
            Ok(ExprResolvedId::PredefinedConstant(p))
        } else {
            eprintln!(
                "error: {}: unresolved identifier \"{}\" in expression",
                item_name, id
            );
            Err(io::ErrorKind::InvalidData)
        }
    }

    pub fn resolve_expr_sizeof_type(
        &self,
        item_name: &str,
        id: &str,
    ) -> Result<ExprResolvedType, io::ErrorKind> {
        let id: &str = &self.translate_aliases(id);
        if let Some(t) = self.lookup(id) {
            Ok(ExprResolvedType::Type(t))
        } else if let Some(p) = PredefinedTypes::lookup(id) {
            Ok(ExprResolvedType::PredefinedType(p))
        } else {
            eprintln!(
                "error: {}: unresolved type name \"{}\" in sizeof expression",
                item_name, id
            );
            Err(io::ErrorKind::InvalidData)
        }
    }

    fn resolve_expr_ids(
        &self,
        item_name: &str,
        e: &mut Expr,
        locals: Option<&[StructureTableEntry]>,
    ) -> Result<(), io::Error> {
        // First substitute CPP-style defines
        self.cpp_expand_expr_ids(item_name, e)?;

        e.resolve_ids(
            &mut |id| self.resolve_expr_id(item_name, id, locals),
            &mut |id| self.resolve_expr_sizeof_type(item_name, id),
        )
        .map_err(io::Error::from)
    }

    fn resolve_value_range_ids(
        &self,
        item_name: &str,
        r: &mut ValueRange,
    ) -> Result<(), io::Error> {
        // First substitute CPP-style defines
        match r {
            ValueRange::Range {
                min_value,
                max_value,
            } => {
                if let Some(min_value) = min_value {
                    self.cpp_expand_expr_ids(item_name, min_value)?;
                }
                if let Some(max_value) = max_value {
                    self.cpp_expand_expr_ids(item_name, max_value)?;
                }
            }
            ValueRange::Discrete(values) => {
                if values.len() == 1 {
                    if let ExprOp::Id(id) = &values[0].op {
                        if let Some(id) = id.name.strip_prefix('$') {
                            let id = id.trim_start();
                            if let Some(replacement) = self.lookup_cppdefine(id) {
                                let repl = ValueRange::parse(replacement);
                                match repl {
                                    Ok(repl) => {
                                        if !repl.1.trim_start().is_empty() {
                                            eprintln!
                                                ("error: {}: excess after value range from \"{}\" CPP-style define",
                                                 item_name, id);
                                            return Err(io::Error::from(
                                                io::ErrorKind::InvalidData,
                                            ));
                                        }
                                        *r = repl.0;
                                        return self.resolve_value_range_ids(item_name, r);
                                    }
                                    Err(reason) => {
                                        eprintln!
                                            ("error: {}: failed to parse value range from \"{}\" CPP-style define: {}",
                                             item_name, id, reason);
                                        return Err(io::Error::from(io::ErrorKind::InvalidData));
                                    }
                                };
                            }
                        }
                    }
                }

                for e in values.iter_mut() {
                    self.cpp_expand_expr_ids(item_name, e)?;
                }
            }
        };

        r.resolve_ids(
            &mut |id| self.resolve_expr_id(item_name, id, None),
            &mut |id| self.resolve_expr_sizeof_type(item_name, id),
        )
        .map_err(io::Error::from)
    }

    fn check_structure_recursion(&self, i: StructuresPartTablesIndex) -> Result<(), io::Error> {
        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
        enum StackEntryTableIndex {
            Structure(StructuresPartTablesStructureIndex),
            Union(StructuresPartTablesUnionIndex),
        }
        struct StackEntry(StackEntryTableIndex, usize);

        let mut stack: Vec<StackEntry> = Vec::new();
        match i {
            StructuresPartTablesIndex::Structure(i) => {
                stack.push(StackEntry(StackEntryTableIndex::Structure(i), 0))
            }
            StructuresPartTablesIndex::Union(i) => {
                stack.push(StackEntry(StackEntryTableIndex::Union(i), 0))
            }
            _ => (),
        };

        while !stack.is_empty() {
            let top = stack.last_mut().unwrap();
            let next_index = match &top.0 {
                StackEntryTableIndex::Structure(i) => {
                    let cur = self.get_structure(*i);
                    if cur.entries.len() == top.1 {
                        stack.pop();
                        continue;
                    }

                    let j = top.1;
                    top.1 += 1;
                    match &cur.entries[j].entry_type {
                        StructureTableEntryType::Plain(t) => {
                            t.resolved_base_type.and_then(|resolved| match resolved {
                                StructureTableEntryResolvedBaseType::Predefined(_) => None,
                                StructureTableEntryResolvedBaseType::Constants(_) => None,
                                StructureTableEntryResolvedBaseType::Bits(_) => None,
                                StructureTableEntryResolvedBaseType::Type(_) => None,
                                StructureTableEntryResolvedBaseType::Structure(resolved) => {
                                    Some(StackEntryTableIndex::Structure(resolved))
                                }
                            })
                        }
                        StructureTableEntryType::Discriminant(_) => None,
                        StructureTableEntryType::Union(t) => {
                            t.resolved_union_type.map(StackEntryTableIndex::Union)
                        }
                        StructureTableEntryType::Array(t) => {
                            t.resolved_element_type.and_then(|resolved| match resolved {
                                StructureTableEntryResolvedBaseType::Predefined(_) => None,
                                StructureTableEntryResolvedBaseType::Constants(_) => None,
                                StructureTableEntryResolvedBaseType::Bits(_) => None,
                                StructureTableEntryResolvedBaseType::Type(_) => None,
                                StructureTableEntryResolvedBaseType::Structure(resolved) => {
                                    Some(StackEntryTableIndex::Structure(resolved))
                                }
                            })
                        }
                    }
                }
                StackEntryTableIndex::Union(i) => {
                    let cur = self.get_union(*i);
                    if cur.entries.len() == top.1 {
                        stack.pop();
                        continue;
                    }

                    let j = top.1;
                    top.1 += 1;
                    match &cur.entries[j].entry_type {
                        UnionTableEntryType::Plain(t) => {
                            t.resolved_base_type.and_then(|resolved| match resolved {
                                UnionTableEntryResolvedBaseType::Predefined(_) => None,
                                UnionTableEntryResolvedBaseType::Constants(_) => None,
                                UnionTableEntryResolvedBaseType::Bits(_) => None,
                                UnionTableEntryResolvedBaseType::Type(_) => None,
                                UnionTableEntryResolvedBaseType::Structure(resolved) => {
                                    Some(StackEntryTableIndex::Structure(resolved))
                                }
                            })
                        }
                        UnionTableEntryType::Array(t) => {
                            t.resolved_element_type.and_then(|resolved| match resolved {
                                UnionTableEntryResolvedBaseType::Predefined(_) => None,
                                UnionTableEntryResolvedBaseType::Constants(_) => None,
                                UnionTableEntryResolvedBaseType::Bits(_) => None,
                                UnionTableEntryResolvedBaseType::Type(_) => None,
                                UnionTableEntryResolvedBaseType::Structure(resolved) => {
                                    Some(StackEntryTableIndex::Structure(resolved))
                                }
                            })
                        }
                    }
                }
            };

            if let Some(next_index) = next_index {
                if stack.iter().any(|e| e.0 == next_index) {
                    match next_index {
                        StackEntryTableIndex::Structure(i) => {
                            eprintln!(
                                "error: table {}: structure contains itself",
                                &self.get_structure(i).name
                            );
                        }
                        StackEntryTableIndex::Union(i) => {
                            eprintln!(
                                "error: table {}: union contains itself",
                                &self.get_union(i).name
                            );
                        }
                    };
                    return Err(io::Error::from(io::ErrorKind::InvalidData));
                }

                stack.push(StackEntry(next_index, 0));
            }
        }

        Ok(())
    }

    fn collect_table_deps(&self, index: StructuresPartTablesIndex) -> ConfigDeps {
        match index {
            StructuresPartTablesIndex::Aliases(index) => {
                let t = self.get_aliases(index);
                t.structures_info.deps.clone()
            }
            StructuresPartTablesIndex::Bits(index) => {
                let t = self.get_bits(index);
                t.structures_info.deps.clone()
            }
            StructuresPartTablesIndex::Constants(index) => {
                let t = self.get_constants(index);
                t.structures_info.deps.clone()
            }
            StructuresPartTablesIndex::Type(index) => {
                let t = self.get_type(index);
                t.structures_info.deps.clone()
            }
            StructuresPartTablesIndex::Structure(index) => {
                let t = self.get_structure(index);
                t.structures_info.deps.clone()
            }
            StructuresPartTablesIndex::Union(index) => {
                let t = self.get_union(index);
                t.structures_info.deps.clone()
            }
        }
    }

    fn collect_alias_config_deps(&self, name: &str) -> ConfigDeps {
        let mut deps = ConfigDeps::new();
        for index in self.lookup_alias(name) {
            let alias = self.get_alias(index);
            deps.merge_from(&alias.deps);
            let index = StructuresPartTablesAliasesIndex::from(index);
            let table = self.get_aliases(index);
            deps.merge_from(&table.structures_info.deps);
        }
        deps
    }

    fn collect_expr_config_deps(&self, e: &Expr) -> ConfigDeps {
        let mut deps = ConfigDeps::new();
        e.map(&mut |e: &Expr, _r: &[()]| {
            match &e.op {
                ExprOp::Id(id) => {
                    if let ExprResolvedId::Constant(index) = id.resolved.as_ref().unwrap() {
                        let c = self.get_constant(*index);
                        deps.merge_from(&c.deps);
                        let index = StructuresPartTablesConstantsIndex::from(*index);
                        let table = self.get_constants(index);
                        deps.merge_from(&table.structures_info.deps);
                    }
                }
                ExprOp::Sizeof(s) => {
                    deps.merge_from(&self.collect_alias_config_deps(&s.name));
                    match s.resolved.as_ref().unwrap() {
                        ExprResolvedType::PredefinedType(_) => (),
                        ExprResolvedType::Type(index) => {
                            deps.merge_from(&self.collect_table_deps(*index));
                        }
                    };
                }
                _ => (),
            };
        });
        deps
    }

    fn collect_value_range_config_deps(&self, r: &ValueRange) -> ConfigDeps {
        let mut deps = ConfigDeps::new();
        match r {
            ValueRange::Range {
                min_value,
                max_value,
            } => {
                if let Some(value) = min_value {
                    deps.merge_from(&self.collect_expr_config_deps(value));
                }
                if let Some(value) = max_value {
                    deps.merge_from(&self.collect_expr_config_deps(value));
                }
            }
            ValueRange::Discrete(values) => {
                for v in values.iter() {
                    deps.merge_from(&self.collect_expr_config_deps(v));
                }
            }
        };
        deps
    }

    fn propagate_config_deps(&mut self) -> Result<(), io::Error> {
        // Finally propagate ConfigDeps "upwards", that is, every user of some entity
        // will inherit its dependencies.
        let mut propagated_some = true;
        while propagated_some {
            propagated_some = false;
            for i in self.iter() {
                match i {
                    StructuresPartTablesIndex::Aliases(i) => {
                        let mut j = 0;
                        let nentries = self.get_aliases(i).entries.len();
                        while j < nentries {
                            let t = self.get_aliases(i);
                            let entry = &t.entries[j];
                            let mut deps = self.collect_alias_config_deps(&entry.target);
                            deps.merge_from(&entry.deps);
                            deps.factor_by(&t.structures_info.deps);
                            if deps != entry.deps {
                                drop(t);
                                let mut t = self.get_aliases_mut(i);
                                t.entries[j].deps = deps;
                                propagated_some = true;
                            }
                            j += 1;
                        }
                    }
                    StructuresPartTablesIndex::Bits(i) => {
                        let t = self.get_bits(i);
                        let mut table_deps = t.structures_info.deps.clone();
                        table_deps.merge_from(&self.collect_alias_config_deps(&t.base));
                        match t.resolved_base.unwrap() {
                            BitsTableResolvedBase::Predefined(_) => (),
                            BitsTableResolvedBase::Constants(index) => {
                                let index = StructuresPartTablesIndex::Constants(index);
                                table_deps.merge_from(&self.collect_table_deps(index));
                            }
                            BitsTableResolvedBase::Type(index) => {
                                let index = StructuresPartTablesIndex::Type(index);
                                table_deps.merge_from(&self.collect_table_deps(index));
                            }
                        };
                        let nentries = t.entries.len();
                        let mut j = 0;
                        drop(t);
                        while j < nentries {
                            let t = self.get_bits(i);
                            let entry = &t.entries[j];
                            let mut entry_deps = ConfigDeps::new();
                            entry_deps.merge_from(
                                &self.collect_expr_config_deps(&entry.bits.min_bit_index),
                            );
                            if let Some(max_bit_index) = entry.bits.max_bit_index.as_ref() {
                                entry_deps
                                    .merge_from(&self.collect_expr_config_deps(max_bit_index));
                            }

                            if entry.deps.is_empty() {
                                // No explicit dependencies recorded at the
                                // member. Absorb everything at the table level.
                                table_deps.merge_from(&entry_deps);
                            } else {
                                // Don't simply update the entries' dependencies.
                                // If there are any already, they're stemming from !ALG macro expansion
                                // and restricting them further might errorneously remove the member
                                // in certain configurations. Bail out if the recorded dependencies are
                                // too weak.
                                entry_deps.factor_by(&table_deps);
                                if !matches!(
                                    entry.deps.partial_cmp(&entry_deps),
                                    Some(cmp::Ordering::Less | cmp::Ordering::Equal)
                                ) {
                                    eprintln!
                                        ("error: table {}: {}: config dependencies weaker than actual requirements",
                                         &t.name, &entry.name);
                                    return Err(io::Error::from(io::ErrorKind::InvalidData));
                                } else {
                                    // No real change, some dependencies might get factored into the
                                    // containing table.
                                    drop(t);
                                    let mut t = self.get_bits_mut(i);
                                    t.entries[j].deps.factor_by(&table_deps);
                                }
                            }
                            j += 1;
                        }
                        let t = self.get_bits(i);
                        for reserved in t.reserved.iter() {
                            let mut reserved_deps = ConfigDeps::new();
                            reserved_deps.merge_from(
                                &self.collect_expr_config_deps(&reserved.min_bit_index),
                            );
                            if let Some(max_bit_index) = reserved.max_bit_index.as_ref() {
                                reserved_deps
                                    .merge_from(&self.collect_expr_config_deps(max_bit_index));
                            }

                            table_deps.merge_from(&reserved_deps);
                        }
                        drop(t);
                        let mut t = self.get_bits_mut(i);
                        propagated_some |= t.structures_info.deps.merge_from(&table_deps);
                    }
                    StructuresPartTablesIndex::Constants(i) => {
                        let t = self.get_constants(i);
                        let mut table_deps = t.structures_info.deps.clone();
                        if let Some(base) = t.base.as_ref() {
                            table_deps.merge_from(&self.collect_alias_config_deps(base));
                        }
                        let nentries = t.entries.len();
                        let mut j = 0;
                        drop(t);
                        while j < nentries {
                            let t = self.get_constants(i);
                            let entry = &t.entries[j];
                            let mut entry_deps = ConfigDeps::new();
                            entry_deps.merge_from(&self.collect_expr_config_deps(&entry.value));

                            if entry.deps.is_empty() {
                                // No explicit dependencies recorded at the
                                // member. Absorb everything at the table level.
                            } else {
                                // Don't simply update the entries' dependencies.
                                // If there are any already, they're stemming from !ALG macro expansion
                                // and restricting them further might errorneously remove the member
                                // in certain configurations. Bail out if the recorded dependencies are
                                // too weak.
                                entry_deps.factor_by(&table_deps);
                                if !matches!(
                                    entry.deps.partial_cmp(&entry_deps),
                                    Some(cmp::Ordering::Less | cmp::Ordering::Equal)
                                ) {
                                    eprintln!
                                        ("error: table {}: {}: config dependencies weaker than actual requirements",
                                         &t.name, &entry.name);
                                    return Err(io::Error::from(io::ErrorKind::InvalidData));
                                } else {
                                    // No real change, some dependencies might get factored into the
                                    // containing table.
                                    drop(t);
                                    let mut t = self.get_constants_mut(i);
                                    t.entries[j].deps.factor_by(&table_deps);
                                }
                            }
                            j += 1;
                        }
                        let mut t = self.get_constants_mut(i);
                        propagated_some |= t.structures_info.deps.merge_from(&table_deps);
                    }
                    StructuresPartTablesIndex::Type(i) => {
                        let t = self.get_type(i);
                        let mut table_deps = t.structures_info.deps.clone();
                        table_deps.merge_from(&self.collect_alias_config_deps(&t.base));
                        match t.resolved_base.unwrap() {
                            TypeTableResolvedBase::Predefined(_) => (),
                            TypeTableResolvedBase::Constants(index) => {
                                let index = StructuresPartTablesIndex::Constants(index);
                                table_deps.merge_from(&self.collect_table_deps(index));
                            }
                            TypeTableResolvedBase::Type(index) => {
                                let index = StructuresPartTablesIndex::Type(index);
                                table_deps.merge_from(&self.collect_table_deps(index));
                            }
                        };
                        let nentries = t.entries.len();
                        let mut j = 0;
                        drop(t);
                        while j < nentries {
                            let t = self.get_type(i);
                            let entry = &t.entries[j];
                            let mut entry_deps = ConfigDeps::new();
                            entry_deps
                                .merge_from(&self.collect_value_range_config_deps(&entry.values));
                            // For type entries, always absorb the entry dependencies at the type entry itself:
                            // a type entry specifies an allowed value (range) and if the prerequisites for
                            // calculating that are not met in a certain configuration, the value (range) is
                            // considered to not being effective and thus, may as well be masked by
                            // the configuration deps.
                            entry_deps.factor_by(&table_deps);
                            if entry_deps != entry.deps {
                                drop(t);
                                let mut t = self.get_type_mut(i);
                                t.entries[j].deps = entry_deps;
                                propagated_some = true;
                            }
                            j += 1;
                        }
                        let mut t = self.get_type_mut(i);
                        propagated_some |= t.structures_info.deps.merge_from(&table_deps);
                    }
                    StructuresPartTablesIndex::Structure(i) => {
                        let t = self.get_structure(i);
                        let mut table_deps = t.structures_info.deps.clone();
                        let nentries = t.entries.len();
                        let mut j = 0;
                        drop(t);
                        while j < nentries {
                            let t = self.get_structure(i);
                            let entry = &t.entries[j];
                            let mut entry_deps = ConfigDeps::new();
                            match &entry.entry_type {
                                StructureTableEntryType::Plain(plain_type) => {
                                    entry_deps.merge_from(
                                        &self.collect_alias_config_deps(&plain_type.base_type),
                                    );
                                    if let Some(range) = plain_type.range.as_ref() {
                                        entry_deps.merge_from(
                                            &self.collect_value_range_config_deps(range),
                                        );
                                    }
                                    let base_type_index = plain_type.resolved_base_type.unwrap();
                                    let base_type_index =
                                        StructuresPartTablesIndex::try_from(base_type_index);
                                    if let Ok(base_type_index) = base_type_index {
                                        entry_deps
                                            .merge_from(&self.collect_table_deps(base_type_index));
                                    }
                                }
                                StructureTableEntryType::Discriminant(discriminant_type) => {
                                    entry_deps.merge_from(&self.collect_alias_config_deps(
                                        &discriminant_type.discriminant_type,
                                    ));
                                    let discriminant_type_index =
                                        discriminant_type.resolved_discriminant_type.unwrap();
                                    let discriminant_type_index =
                                        StructureTableEntryResolvedBaseType::from(
                                            discriminant_type_index,
                                        );
                                    let discriminant_type_index =
                                        StructuresPartTablesIndex::try_from(
                                            discriminant_type_index,
                                        );
                                    if let Ok(discriminant_type_index) = discriminant_type_index {
                                        entry_deps.merge_from(
                                            &self.collect_table_deps(discriminant_type_index),
                                        );
                                    }
                                }
                                StructureTableEntryType::Union(union_type) => {
                                    entry_deps.merge_from(
                                        &self.collect_alias_config_deps(&union_type.union_type),
                                    );
                                    let union_type_index = union_type.resolved_union_type.unwrap();
                                    let union_type_index =
                                        StructuresPartTablesIndex::Union(union_type_index);
                                    entry_deps
                                        .merge_from(&self.collect_table_deps(union_type_index));
                                }
                                StructureTableEntryType::Array(array_type) => {
                                    entry_deps.merge_from(
                                        &self.collect_alias_config_deps(&array_type.element_type),
                                    );
                                    entry_deps.merge_from(
                                        &self.collect_expr_config_deps(&array_type.size),
                                    );
                                    if let Some(range) = array_type.size_range.as_ref() {
                                        entry_deps.merge_from(
                                            &self.collect_value_range_config_deps(range),
                                        );
                                    }
                                    let element_type_index =
                                        array_type.resolved_element_type.unwrap();
                                    let element_type_index =
                                        StructuresPartTablesIndex::try_from(element_type_index);
                                    if let Ok(element_type_index) = element_type_index {
                                        entry_deps.merge_from(
                                            &self.collect_table_deps(element_type_index),
                                        );
                                    }
                                }
                            }

                            if entry.deps.is_empty() {
                                // No explicit dependencies recorded at the
                                // member. Absorb everything at the table level.
                                table_deps.merge_from(&entry_deps);
                            } else {
                                // Don't simply update the entries' dependencies.
                                // If there are any already, they're stemming from !ALG macro expansion
                                // and restricting them further might errorneously remove the member
                                // in certain configurations. Bail out if the recorded dependencies are
                                // too weak.
                                entry_deps.factor_by(&table_deps);
                                if !matches!(
                                    entry.deps.partial_cmp(&entry_deps),
                                    Some(cmp::Ordering::Less | cmp::Ordering::Equal)
                                ) {
                                    eprintln!
                                        ("error: table {}: {}: config dependencies weaker than actual requirements",
                                         &t.name, &entry.name);
                                    return Err(io::Error::from(io::ErrorKind::InvalidData));
                                } else {
                                    // No real change, some dependencies might get factored into the
                                    // containing table.
                                    drop(t);
                                    let mut t = self.get_structure_mut(i);
                                    t.entries[j].deps.factor_by(&table_deps);
                                }
                            }
                            j += 1;
                        }
                        let mut t = self.get_structure_mut(i);
                        if t.structures_info.deps.merge_from(&table_deps) {
                            propagated_some = true;
                        }
                        propagated_some |= t.structures_info.deps.merge_from(&table_deps);
                    }
                    StructuresPartTablesIndex::Union(i) => {
                        let t = self.get_union(i);
                        let mut table_deps = t.structures_info.deps.clone();
                        let nentries = t.entries.len();
                        let mut j = 0;
                        drop(t);
                        while j < nentries {
                            let t = self.get_union(i);
                            let entry = &t.entries[j];
                            let mut entry_deps = ConfigDeps::new();
                            match &entry.entry_type {
                                UnionTableEntryType::Plain(plain_type) => {
                                    if let Some(base_type) = plain_type.base_type.as_ref() {
                                        entry_deps
                                            .merge_from(&self.collect_alias_config_deps(base_type));
                                        let base_type_index =
                                            plain_type.resolved_base_type.unwrap();
                                        let base_type_index =
                                            StructuresPartTablesIndex::try_from(base_type_index);
                                        if let Ok(base_type_index) = base_type_index {
                                            entry_deps.merge_from(
                                                &self.collect_table_deps(base_type_index),
                                            );
                                        }
                                    }
                                }
                                UnionTableEntryType::Array(array_type) => {
                                    entry_deps.merge_from(
                                        &self.collect_alias_config_deps(&array_type.element_type),
                                    );
                                    entry_deps.merge_from(
                                        &self.collect_expr_config_deps(&array_type.size),
                                    );
                                    let element_type_index =
                                        array_type.resolved_element_type.unwrap();
                                    let element_type_index =
                                        StructuresPartTablesIndex::try_from(element_type_index);
                                    if let Ok(element_type_index) = element_type_index {
                                        entry_deps.merge_from(
                                            &self.collect_table_deps(element_type_index),
                                        );
                                    }
                                }
                            }

                            let mut selector_deps = ConfigDeps::new();
                            if let Some(selector) = entry.selector.as_ref() {
                                if let Some(index) = self.lookup_constant(selector) {
                                    let constants_entry = self.get_constant(index);
                                    selector_deps.merge_from(&constants_entry.deps);
                                    let index = StructuresPartTablesConstantsIndex::from(index);
                                    let constants_table = self.get_constants(index);
                                    selector_deps.merge_from(&constants_table.structures_info.deps);
                                }
                            }
                            entry_deps.factor_by(&selector_deps);

                            if entry.deps.is_empty() {
                                // No explicit dependencies recorded at the
                                // member. Absorb everything at the table level.
                                table_deps.merge_from(&entry_deps);
                            } else {
                                // Don't simply update the entries' dependencies.
                                // If there are any already, they're stemming from !ALG macro expansion
                                // and restricting them further might errorneously remove the member
                                // in certain configurations. Bail out if the recorded dependencies are
                                // too weak.
                                entry_deps.factor_by(&table_deps);
                                if !matches!(
                                    entry.deps.partial_cmp(&entry_deps),
                                    Some(cmp::Ordering::Less | cmp::Ordering::Equal)
                                ) {
                                    eprintln!
                                        ("error: table {}: {}: config dependencies weaker than actual requirements",
                                         &t.name, &entry.name);
                                    return Err(io::Error::from(io::ErrorKind::InvalidData));
                                } else {
                                    // No real change, some dependencies might get factored into the
                                    // containing table.
                                    drop(t);
                                    let mut t = self.get_union_mut(i);
                                    t.entries[j].deps.factor_by(&table_deps);
                                }
                            }
                            j += 1;
                        }
                        let mut t = self.get_union_mut(i);
                        propagated_some |= t.structures_info.deps.merge_from(&table_deps);
                    }
                };
            }
        }

        // When done with propagating, verify that no structure's discriminant
        // or union entries have individual dependencies assigned to
        // them. Supporting that would be a nightmare, or impossible even in
        // certain combinations. Also, array members' individual configuration
        // dependencies must be stricter than any local members contributing to
        // the length calculation.
        for i in self.iter() {
            if let StructuresPartTablesIndex::Structure(i) = i {
                let t = self.get_structure(i);
                for entry in t.entries.iter() {
                    match &entry.entry_type {
                        StructureTableEntryType::Array(array_type) => {
                            let result = array_type.size.map(&mut |e,
                                                                   subexpr_result: &[Result<
                                (),
                                io::Error,
                            >]| {
                                if subexpr_result.iter().any(|r| r.is_err()) {
                                    return Err(io::Error::from(io::ErrorKind::InvalidData));
                                }
                                if let ExprOp::Id(id) = &e.op {
                                    if let ExprResolvedId::StructMember(j) =
                                        id.resolved.as_ref().unwrap()
                                    {
                                        let size_member_entry = &t.entries[*j];
                                        if !size_member_entry.deps.is_implied_by(&entry.deps) {
                                            return Err(io::Error::from(
                                                io::ErrorKind::InvalidData,
                                            ));
                                        }
                                    }
                                }
                                Ok(())
                            });
                            if let Err(e) = result {
                                eprintln!
                                    ("error: table {}: {}: array member has weaker config dependencies than size member",
                                     &t.name, &entry.name);
                                return Err(e);
                            }
                        }
                        StructureTableEntryType::Discriminant(_) => {
                            if entry.deps.is_unconditional_true() {
                                continue;
                            }
                            eprintln!
                                ("error: table {}: {}: non-trivial config dependencies for discriminant member",
                                 &t.name, &entry.name);
                            return Err(io::Error::from(io::ErrorKind::InvalidData));
                        }
                        StructureTableEntryType::Union(_) => {
                            if entry.deps.is_unconditional_true() {
                                continue;
                            }
                            eprintln!
                                ("error: table {}: {}: non-trivial config dependencies for union member",
                                 &t.name, &entry.name);
                            return Err(io::Error::from(io::ErrorKind::InvalidData));
                        }
                        _ => (),
                    };
                }
            }
        }

        Ok(())
    }

    pub(in super::super::super) fn resolve_all(&mut self) -> Result<(), io::Error> {
        let indices: Vec<_> = self.iter().collect();
        for i in indices {
            match i {
                StructuresPartTablesIndex::Constants(i) => {
                    let mut t = self.get_constants_mut(i);
                    let base = {
                        match &t.base {
                            Some(base) => {
                                let translated_base: &str = &self.translate_aliases(base);
                                match PredefinedTypes::lookup(translated_base) {
                                    Some(resolved) => Some(resolved),
                                    None => {
                                        eprintln!(
                                            "error: table {}: invalid base type {}",
                                            t.name, base
                                        );
                                        return Err(io::Error::from(io::ErrorKind::InvalidData));
                                    }
                                }
                            }
                            None => None,
                        }
                    };
                    t.resolved_base = base;
                    if t.resolved_base.is_some() {
                        // This Constants table might serve as an union
                        // discriminant, set the corresponding flag. It might
                        // get unset later after constant evaluation, in case
                        // there are e.g. conflicting values.
                        t.enum_like = true;
                    }

                    if let Some(error_rc) = &t.error_rc {
                        let resolved_error_rc = self.lookup_constant(error_rc);
                        if resolved_error_rc.is_none() {
                            eprintln!(
                                "error: table {}: failed to resolve error code {}",
                                t.name, &error_rc
                            );
                            return Err(io::Error::from(io::ErrorKind::InvalidData));
                        }
                        t.resolved_error_rc = resolved_error_rc;
                    }

                    for j in 0..t.entries.len() {
                        let entry = &mut t.entries[j];
                        self.resolve_expr_ids(&entry.name, &mut entry.value, None)?;
                    }
                }
                StructuresPartTablesIndex::Bits(i) => {
                    let mut t = self.get_bits_mut(i);
                    let base = {
                        let translated_base: &str = &self.translate_aliases(&t.base);
                        if let Some(resolved) = self.lookup(translated_base) {
                            match resolved {
                                StructuresPartTablesIndex::Constants(resolved) => {
                                    if self.get_constants(resolved).base.is_none() {
                                        eprintln!("error: table {}: constants base type {} with no base type itself",
                                                  t.name, translated_base);
                                        return Err(io::Error::from(io::ErrorKind::InvalidData));
                                    }
                                    BitsTableResolvedBase::Constants(resolved)
                                }
                                StructuresPartTablesIndex::Type(resolved) => {
                                    BitsTableResolvedBase::Type(resolved)
                                }
                                _ => {
                                    eprintln!(
                                        "error: table {}: invalid base type {}",
                                        t.name, &t.base
                                    );
                                    return Err(io::Error::from(io::ErrorKind::InvalidData));
                                }
                            }
                        } else if let Some(resolved) = PredefinedTypes::lookup(translated_base) {
                            BitsTableResolvedBase::Predefined(resolved)
                        } else {
                            eprintln!("error: table {}: base type {} not found", t.name, &t.base);
                            return Err(io::Error::from(io::ErrorKind::InvalidData));
                        }
                    };
                    t.resolved_base = Some(base);

                    let (table_name, mut entries) =
                        RefMut::map_split(t, |t| (&mut t.name, &mut t.entries));
                    for j in 0..entries.len() {
                        let entry = &mut entries[j];
                        self.resolve_expr_ids(&table_name, &mut entry.bits.min_bit_index, None)?;
                        if let Some(max_bit_index) = &mut entry.bits.max_bit_index {
                            self.resolve_expr_ids(&table_name, max_bit_index, None)?;
                        }
                    }
                    drop(table_name);
                    drop(entries);
                    let t = self.get_bits_mut(i);
                    let (table_name, mut reserved) =
                        RefMut::map_split(t, |t| (&mut t.name, &mut t.reserved));
                    for reserved in reserved.iter_mut() {
                        self.resolve_expr_ids(&table_name, &mut reserved.min_bit_index, None)?;
                        if let Some(max_bit_index) = &mut reserved.max_bit_index {
                            self.resolve_expr_ids(&table_name, max_bit_index, None)?;
                        }
                    }
                }
                StructuresPartTablesIndex::Type(i) => {
                    let mut t = self.get_type_mut(i);
                    let base = {
                        let translated_base: &str = &self.translate_aliases(&t.base);
                        if let Some(resolved) = self.lookup(translated_base) {
                            match resolved {
                                StructuresPartTablesIndex::Constants(resolved) => {
                                    TypeTableResolvedBase::Constants(resolved)
                                }
                                StructuresPartTablesIndex::Type(resolved) => {
                                    TypeTableResolvedBase::Type(resolved)
                                }
                                _ => {
                                    eprintln!(
                                        "error: table {}: invalid base type {}",
                                        t.name, &t.base
                                    );
                                    return Err(io::Error::from(io::ErrorKind::InvalidData));
                                }
                            }
                        } else if let Some(resolved) = PredefinedTypes::lookup(translated_base) {
                            TypeTableResolvedBase::Predefined(resolved)
                        } else {
                            eprintln!("error: table {}: base type {} not found", t.name, &t.base);
                            return Err(io::Error::from(io::ErrorKind::InvalidData));
                        }
                    };
                    t.resolved_base = Some(base);

                    if let Some(error_rc) = &t.error_rc {
                        let resolved_error_rc = self.lookup_constant(error_rc);
                        if resolved_error_rc.is_none() {
                            eprintln!(
                                "error: table {}: failed to resolve error code {}",
                                t.name, &error_rc
                            );
                            return Err(io::Error::from(io::ErrorKind::InvalidData));
                        }
                        t.resolved_error_rc = resolved_error_rc;
                    }

                    // Check for base type loops.
                    let mut cur_base = t.resolved_base;
                    while let Some(cur) = &cur_base {
                        match cur {
                            TypeTableResolvedBase::Type(cur) => {
                                if cur == &i {
                                    eprintln!("error: table {}: base type chain loop", t.name);
                                    return Err(io::Error::from(io::ErrorKind::InvalidData));
                                }

                                cur_base = self.get_type(*cur).resolved_base;
                            }
                            TypeTableResolvedBase::Constants(_)
                            | TypeTableResolvedBase::Predefined(_) => {
                                cur_base = None;
                            }
                        }
                    }

                    let mut enum_like = t.enum_like;
                    let (table_name, mut entries) =
                        RefMut::map_split(t, |t| (&mut t.name, &mut t.entries));
                    let mut j = 0;
                    while j < entries.len() {
                        let entry = &mut entries[j];
                        self.resolve_value_range_ids(&table_name, &mut entry.values)?;
                        match &entry.values {
                            ValueRange::Discrete(values) => {
                                // After CPP-define replacement has happened, transform
                                // arrays of multiple elements into individual type entries so
                                // that their ConfigDeps, if any, can be tracked individually.
                                if values.len() > 1 {
                                    assert!(!entry.conditional);
                                    let mut entry = entries.remove(j);
                                    let values = match &mut entry.values {
                                        ValueRange::Discrete(values) => values,
                                        _ => unreachable!(),
                                    };

                                    while let Some(value) = values.pop() {
                                        let value = Vec::from([value]);
                                        let value = ValueRange::Discrete(value);
                                        entries.insert(
                                            j,
                                            TypeTableEntry {
                                                values: value,
                                                conditional: false,
                                                deps: entry.deps.clone(),
                                            },
                                        );
                                    }
                                    continue;
                                } else {
                                    match &values[0].op {
                                        ExprOp::Id(_) => (),
                                        _ => enum_like = false,
                                    };
                                }
                            }
                            _ => {
                                enum_like = false;
                            }
                        };
                        j += 1;
                    }
                    if !enum_like {
                        drop(table_name);
                        drop(entries);
                        let mut table = self.get_type_mut(i);
                        table.enum_like = false;
                    }
                }
                StructuresPartTablesIndex::Structure(i) => {
                    let mut t = self.get_structure_mut(i);

                    if let Some(error_rc) = &t.error_rc {
                        let resolved_error_rc = self.lookup_constant(error_rc);
                        if resolved_error_rc.is_none() {
                            eprintln!(
                                "error: table {}: failed to resolve error code {}",
                                t.name, &error_rc
                            );
                            return Err(io::Error::from(io::ErrorKind::InvalidData));
                        }
                        t.resolved_error_rc = resolved_error_rc;
                    }

                    let (table_name, mut entries) =
                        RefMut::map_split(t, |t| (&mut t.name, &mut t.entries));
                    let entries_len = entries.len();
                    for j in 0..entries_len {
                        let (locals, remaining) = entries.split_at_mut(j);
                        let entry = &mut remaining[0];

                        match &mut entry.entry_type {
                            StructureTableEntryType::Plain(plain_type) => {
                                let resolved_base_type = {
                                    let translated_base_type: &str =
                                        &self.translate_aliases(&plain_type.base_type);
                                    match self.lookup(translated_base_type) {
                                        Some(resolved) => {
                                            match StructureTableEntryResolvedBaseType::try_from(
                                                resolved,
                                            ) {
                                                Ok(resolved) => {
                                                    if plain_type.is_size_specifier {
                                                        match resolved {
                                                            StructureTableEntryResolvedBaseType::Predefined(_) |
                                                            StructureTableEntryResolvedBaseType::Constants(_) |
                                                            StructureTableEntryResolvedBaseType::Type(_) => (),
                                                            _ => {
                                                                eprintln!("error: table {}: type {} invalid for size",
                                                                          table_name, &plain_type.base_type);
                                                                return Err(io::Error::from(io::ErrorKind::InvalidData));
                                                            },
                                                        };
                                                    };
                                                    resolved
                                                }
                                                Err(_) => {
                                                    eprintln!("error: table {}: type {} not suitable for plain member",
                                                              table_name, &plain_type.base_type);
                                                    return Err(io::Error::from(
                                                        io::ErrorKind::InvalidData,
                                                    ));
                                                }
                                            }
                                        }
                                        None => {
                                            match PredefinedTypes::lookup(translated_base_type) {
                                                Some(resolved) => {
                                                    StructureTableEntryResolvedBaseType::Predefined(
                                                        resolved,
                                                    )
                                                }
                                                None => {
                                                    eprintln!(
                                                        "error: table {}: type {} not found",
                                                        table_name, &plain_type.base_type
                                                    );
                                                    return Err(io::Error::from(
                                                        io::ErrorKind::InvalidData,
                                                    ));
                                                }
                                            }
                                        }
                                    }
                                };
                                plain_type.resolved_base_type = Some(resolved_base_type);

                                match &mut plain_type.range {
                                    Some(range) => {
                                        self.resolve_value_range_ids(&table_name, range)?
                                    }
                                    None => (),
                                };
                            }
                            StructureTableEntryType::Discriminant(_) => unreachable!(),
                            StructureTableEntryType::Union(union_type) => {
                                let resolved_union_type = {
                                    let translated_union_type: &str =
                                        &self.translate_aliases(&union_type.union_type);
                                    match self.lookup(translated_union_type) {
                                        Some(resolved) => match resolved {
                                            StructuresPartTablesIndex::Union(resolved) => resolved,
                                            _ => {
                                                eprintln!(
                                                    "error: table {}: type {} not an union",
                                                    table_name, &union_type.union_type
                                                );
                                                return Err(io::Error::from(
                                                    io::ErrorKind::InvalidData,
                                                ));
                                            }
                                        },
                                        None => {
                                            eprintln!(
                                                "error: table {}: union type {} not found",
                                                table_name, &union_type.union_type
                                            );
                                            return Err(io::Error::from(
                                                io::ErrorKind::InvalidData,
                                            ));
                                        }
                                    }
                                };
                                union_type.resolved_union_type = Some(resolved_union_type);

                                match locals
                                    .iter()
                                    .position(|l| l.name == union_type.discriminant)
                                {
                                    Some(j) => {
                                        union_type.resolved_discriminant = Some(j);
                                    }
                                    None => {
                                        eprintln!(
                                            "error: table {}: union discriminant {} not found",
                                            table_name, &union_type.discriminant
                                        );
                                        return Err(io::Error::from(io::ErrorKind::InvalidData));
                                    }
                                };

                                let discriminant =
                                    &mut locals[union_type.resolved_discriminant.unwrap()];
                                let resolved_discriminant_type = match &mut discriminant.entry_type
                                {
                                    StructureTableEntryType::Plain(plain_type) => {
                                        let plain_type = plain_type.clone();
                                        match StructureTableEntryDiscriminantType::try_from(
                                            plain_type,
                                        ) {
                                            Ok(mut discriminant_type) => {
                                                let resolved_discriminant_type = discriminant_type
                                                    .resolved_discriminant_type
                                                    .unwrap();
                                                discriminant_type
                                                    .discriminated_union_members
                                                    .push(j);
                                                discriminant.entry_type =
                                                    StructureTableEntryType::Discriminant(
                                                        discriminant_type,
                                                    );
                                                resolved_discriminant_type
                                            }
                                            Err(_) => {
                                                eprintln!
                                                    ("error: table {}: member {} not suitable as union discriminant",
                                                     table_name, &discriminant.name);
                                                return Err(io::Error::from(
                                                    io::ErrorKind::InvalidData,
                                                ));
                                            }
                                        }
                                    }
                                    StructureTableEntryType::Discriminant(discriminant_type) => {
                                        discriminant_type.discriminated_union_members.push(j);
                                        discriminant_type.resolved_discriminant_type.unwrap()
                                    }
                                    _ => {
                                        eprintln!("error: table {}: member {} not suitable as union discriminant",
                                                  table_name, &discriminant.name);
                                        return Err(io::Error::from(io::ErrorKind::InvalidData));
                                    }
                                };

                                // If this structure is a "tagged union", register at the union table.
                                if entries_len == 2 {
                                    let mut union_table =
                                        self.get_union_mut(union_type.resolved_union_type.unwrap());
                                    union_table.tagged_unions.add(resolved_discriminant_type, i);
                                }
                            }
                            StructureTableEntryType::Array(array_type) => {
                                let resolved_element_type = {
                                    let translated_element_type: &str =
                                        &self.translate_aliases(&array_type.element_type);
                                    match self.lookup(translated_element_type) {
                                        Some(resolved) => {
                                            match StructureTableEntryResolvedBaseType::try_from(
                                                resolved,
                                            ) {
                                                Ok(resolved) => resolved,
                                                Err(_) => {
                                                    eprintln!("error: table {}: type {} not suitable for array member",
                                                              table_name, &array_type.element_type);
                                                    return Err(io::Error::from(
                                                        io::ErrorKind::InvalidData,
                                                    ));
                                                }
                                            }
                                        }
                                        None => {
                                            match PredefinedTypes::lookup(translated_element_type) {
                                                Some(resolved) => {
                                                    StructureTableEntryResolvedBaseType::Predefined(
                                                        resolved,
                                                    )
                                                }
                                                None => {
                                                    eprintln!(
                                                        "error: table {}: type {} not found",
                                                        table_name, &array_type.element_type
                                                    );
                                                    return Err(io::Error::from(
                                                        io::ErrorKind::InvalidData,
                                                    ));
                                                }
                                            }
                                        }
                                    }
                                };
                                array_type.resolved_element_type = Some(resolved_element_type);

                                self.resolve_expr_ids(
                                    &table_name,
                                    &mut array_type.size,
                                    Some(locals),
                                )?;
                                match &mut array_type.size_range {
                                    Some(range) => {
                                        self.resolve_value_range_ids(&table_name, range)?
                                    }
                                    None => (),
                                };
                            }
                        };
                    }
                    drop(table_name);
                    drop(entries);

                    self.check_structure_recursion(StructuresPartTablesIndex::Structure(i))?;
                }
                StructuresPartTablesIndex::Union(i) => {
                    let t = self.get_union_mut(i);
                    let (table_name, mut entries) =
                        RefMut::map_split(t, |t| (&mut t.name, &mut t.entries));
                    for j in 0..entries.len() {
                        let entry = &mut entries[j];
                        match &mut &mut entry.entry_type {
                            UnionTableEntryType::Plain(plain_type) => {
                                match &plain_type.base_type {
                                    Some(base_type) => {
                                        let resolved_base_type = {
                                            let translated_base_type: &str =
                                                &self.translate_aliases(base_type);
                                            match self.lookup(translated_base_type) {
                                                Some(resolved) => {
                                                    match UnionTableEntryResolvedBaseType::try_from(
                                                        resolved,
                                                    ) {
                                                        Ok(resolved) => resolved,
                                                        Err(_) => {
                                                            eprintln!
                                                              ("error: table {}: type {} not suitable for plain member",
                                                               table_name, base_type);
                                                            return Err(io::Error::from(
                                                                io::ErrorKind::InvalidData,
                                                            ));
                                                        }
                                                    }
                                                }
                                                None => {
                                                    match PredefinedTypes::lookup(translated_base_type) {
                                                        Some(resolved) => {
                                                            UnionTableEntryResolvedBaseType::Predefined(resolved)
                                                        },
                                                        None => {
                                                            eprintln!("error: table {}: type {} not found",
                                                                      table_name, base_type);
                                                            return Err(io::Error::from(io::ErrorKind::InvalidData));
                                                        },
                                                    }
                                                }
                                            }
                                        };
                                        plain_type.resolved_base_type = Some(resolved_base_type);
                                    }
                                    None => (),
                                };
                            }
                            UnionTableEntryType::Array(array_type) => {
                                let resolved_element_type = {
                                    let translated_element_type: &str =
                                        &self.translate_aliases(&array_type.element_type);
                                    match self.lookup(translated_element_type) {
                                        Some(resolved) => {
                                            match UnionTableEntryResolvedBaseType::try_from(
                                                resolved,
                                            ) {
                                                Ok(resolved) => resolved,
                                                Err(_) => {
                                                    eprintln!("error: table {}: type {} not suitable for array member",
                                                              table_name, &array_type.element_type);
                                                    return Err(io::Error::from(
                                                        io::ErrorKind::InvalidData,
                                                    ));
                                                }
                                            }
                                        }
                                        None => {
                                            match PredefinedTypes::lookup(translated_element_type) {
                                                Some(resolved) => {
                                                    UnionTableEntryResolvedBaseType::Predefined(
                                                        resolved,
                                                    )
                                                }
                                                None => {
                                                    eprintln!(
                                                        "error: table {}: type {} not found",
                                                        table_name, &array_type.element_type
                                                    );
                                                    return Err(io::Error::from(
                                                        io::ErrorKind::InvalidData,
                                                    ));
                                                }
                                            }
                                        }
                                    }
                                };
                                array_type.resolved_element_type = Some(resolved_element_type);

                                self.resolve_expr_ids(&table_name, &mut array_type.size, None)?;
                            }
                        };
                    }
                    drop(table_name);
                    drop(entries);

                    self.check_structure_recursion(StructuresPartTablesIndex::Union(i))?;
                }
                StructuresPartTablesIndex::Aliases(_i) => (),
            };
        }

        // After having sorted out recursions, check that all structure members
        // with a 'conditional' enablement flag set do indeed have a conditional
        // base type. While at it, verify that all union discrimants' types are
        // enum-like and that each associated union has got a member for each
        // possible value.
        for i in self.iter() {
            let i = match i {
                StructuresPartTablesIndex::Structure(i) => i,
                _ => continue,
            };

            let s = self.get_structure(i);
            for entry in s.entries.iter() {
                let (type_name, conditional_type) = match &entry.entry_type {
                    StructureTableEntryType::Plain(plain_type) => {
                        if !plain_type.base_type_conditional
                            && !plain_type.base_type_enable_conditional
                        {
                            continue;
                        }
                        (
                            &plain_type.base_type,
                            plain_type.resolved_base_type.unwrap(),
                        )
                    }
                    StructureTableEntryType::Discriminant(discriminant_type) => {
                        if !discriminant_type.discriminant_type_conditional
                            && !discriminant_type.discriminant_type_enable_conditional
                        {
                            continue;
                        }
                        let resolved_type = discriminant_type.resolved_discriminant_type.unwrap();
                        let resolved_type =
                            StructureTableEntryResolvedBaseType::from(resolved_type);
                        (&discriminant_type.discriminant_type, resolved_type)
                    }
                    StructureTableEntryType::Array(array_type) => {
                        if !array_type.element_type_conditional
                            && !array_type.element_type_enable_conditional
                        {
                            continue;
                        }
                        (
                            &array_type.element_type,
                            array_type.resolved_element_type.unwrap(),
                        )
                    }
                    _ => continue,
                };

                // Carrying conditional flags through typedefs would potentially
                // require multiple variants of those and is not currently
                // supported (or needed for that matter).
                match self.lookup_alias(type_name).count() {
                    0 => (),
                    _ => {
                        eprintln!(
                            "error: table {}: {}: conditional alias types unsupported",
                            &s.name, &entry.name
                        );
                        return Err(io::Error::from(io::ErrorKind::InvalidData));
                    }
                };

                match conditional_type {
                    StructureTableEntryResolvedBaseType::Type(index) => {
                        let t = self.get_type(index);
                        if t.conditional {
                            continue;
                        }
                    }
                    StructureTableEntryResolvedBaseType::Structure(index) => {
                        let t = self.get_structure(index);
                        if t.conditional {
                            continue;
                        }
                    }
                    _ => (),
                };
                eprintln!(
                    "error: table {}: {}: conditional flag on unconditional type",
                    &s.name, &entry.name
                );
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }
        }

        // Finally propagate ConfigDeps "upwards", that is, every user of some entity
        // will inherit its dependencies.
        self.propagate_config_deps()?;

        Ok(())
    }
}
