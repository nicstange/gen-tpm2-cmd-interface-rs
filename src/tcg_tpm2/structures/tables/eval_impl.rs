// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

use std::cell::RefMut;
use std::cmp;
use std::io;

use super::super::expr::{Expr, ExprOp, ExprResolvedId, ExprResolvedType, ExprValue};
use super::super::predefined::PredefinedTypeRef;
use super::super::predefined::{PredefinedConstantRef, PredefinedTypes};
use super::super::structure_table::{
    StructureTableEntryResolvedBaseType, StructureTableEntryResolvedDiscriminantType,
    StructureTableEntryType,
};
use super::super::type_table::TypeTableResolvedBase;
use super::super::union_table::UnionTableEntryType;
use super::super::value_range::ValueRange;
use std::collections::HashSet;

use super::{
    StructuresPartTables, StructuresPartTablesConstantIndex, StructuresPartTablesIndex,
    StructuresPartTablesStructureIndex, StructuresPartTablesUnionIndex, UnionSelectorIterator,
};

impl StructuresPartTables {
    fn find_type_table_underlying_type(
        &self,
        table_name: &str,
        mut base: TypeTableResolvedBase,
    ) -> Result<PredefinedTypeRef, io::Error> {
        loop {
            match base {
                TypeTableResolvedBase::Predefined(predefined) => {
                    break Ok(predefined);
                }
                TypeTableResolvedBase::Constants(index) => {
                    let constants = self.get_constants(index);
                    if let Some(predefined) = constants.resolved_base {
                        break Ok(predefined);
                    } else {
                        eprintln!("error: table {}: base type chain stops at constants type {} with no base",
                                  table_name, constants.name);
                        break Err(io::Error::from(io::ErrorKind::InvalidData));
                    }
                }
                TypeTableResolvedBase::Type(index) => {
                    base = self.get_type(index).resolved_base.unwrap();
                }
            }
        }
    }

    fn try_eval_expr(&self, item_name: &str, e: &mut Expr) -> Result<bool, ()> {
        if e.value.is_some() {
            return Ok(true);
        }

        e.transform_in_place(&mut |e: &mut Expr, r: &[Result<bool, ()>]| -> Result<bool, ()> {
            if e.value.is_some() {
                return Ok(true);
            }
            match &e.op {
                ExprOp::Hex(_) |
                ExprOp::Dec(_) => unreachable!(),
                ExprOp::Id(id) => {
                    match id.resolved.as_ref().unwrap() {
                        ExprResolvedId::PredefinedConstant(c) => {
                            let mut deps = HashSet::new();
                            deps.insert(*c);
                            e.value = Some(ExprValue::RuntimeConstant(deps));
                            Ok(true)
                        },
                        ExprResolvedId::Constant(index) => {
                            let constant = self.get_constant(*index);
                            match &constant.value.value {
                                Some(value) => {
                                    e.value = Some(value.clone());
                                    Ok(true)
                                },
                                None => Ok(false),
                            }
                        },
                        ExprResolvedId::StructMember(_) => {
                            e.value = Some(ExprValue::Dynamic);
                            Ok(true)
                        },
                    }
                },
                ExprOp::Sizeof(s) => {
                    match s.resolved.as_ref().unwrap() {
                        ExprResolvedType::PredefinedType(predefined) => {
                            e.value = Some(ExprValue::from(predefined.bits / 8));
                            Ok(true)
                            },
                        ExprResolvedType::Type(index) => {
                            match index {
                                StructuresPartTablesIndex::Constants(index) => {
                                    let table = self.get_constants(*index);
                                    if let Some(size) = &table.size {
                                        e.value = Some(size.clone());
                                        Ok(true)
                                    } else {
                                        eprintln!("error: {}: sizeof applied to constants type \"{}\" with no base",
                                                  item_name, &table.name);
                                        Err(())
                                    }
                                },
                                StructuresPartTablesIndex::Bits(index) => {
                                    let table = self.get_bits(*index);
                                    e.value = Some(table.size.as_ref().unwrap().clone());
                                    Ok(true)
                                },
                                StructuresPartTablesIndex::Type(index) => {
                                    let table = self.get_type(*index);
                                    e.value = Some(table.size.as_ref().unwrap().clone());
                                    Ok(true)
                                },
                                StructuresPartTablesIndex::Structure(index) => {
                                    let table = self.get_structure(*index);
                                    e.value = table.max_size.clone();
                                    Ok(e.value.is_some())
                                },
                                StructuresPartTablesIndex::Union(index) => {
                                    let table = self.get_union(*index);
                                    e.value = table.max_size.clone();
                                    Ok(e.value.is_some())
                                },
                                StructuresPartTablesIndex::Aliases(_) => unreachable!(),
                            }
                        }
                    }
                },
                ExprOp::Add(e0, e1) => {
                    match r[0] {
                        Ok(true) => {
                            match r[1] {
                                Ok(true) => {
                                    let v0 = e0.value.as_ref().unwrap().clone();
                                    let v1 = e1.value.as_ref().unwrap().clone();
                                    match v0 + v1 {
                                        Ok(v) => {
                                            e.value = Some(v);
                                            Ok(true)
                                        },
                                        Err(_) => {
                                            eprintln!("error: {}: integer overflow in constant addition expression",
                                                      item_name);
                                            Err(())
                                        }
                                    }
                                },
                                Ok(false) => Ok(false),
                                Err(_) => r[1],
                            }
                        },
                        Ok(false) => {
                            match r[1] {
                                Ok(_) => Ok(false),
                                Err(_) => r[1],
                            }
                        },
                        Err(_) => r[0],
                    }
                },
                ExprOp::Sub(e0, e1)  => {
                    match r[0] {
                        Ok(true) => {
                            match r[1] {
                                Ok(true) => {
                                    let v0 = e0.value.as_ref().unwrap().clone();
                                    let v1 = e1.value.as_ref().unwrap().clone();
                                    match v0 - v1 {
                                        Ok(v) => {
                                            e.value = Some(v);
                                            Ok(true)
                                        },
                                        Err(_) => {
                                            eprintln!("error: {}: integer overflow in constant subtraction expression",
                                                      item_name);
                                            Err(())
                                        }
                                    }
                                },
                                Ok(false) => Ok(false),
                                Err(_) => r[1],
                            }
                        },
                        Ok(false) => {
                            match r[1] {
                                Ok(_) => Ok(false),
                                Err(_) => r[1],
                            }
                        },
                        Err(_) => r[0],
                    }
                },
                ExprOp::Mul(e0, e1) => {
                    match r[0] {
                        Ok(true) => {
                            match r[1] {
                                Ok(true) => {
                                    let v0 = e0.value.as_ref().unwrap().clone();
                                    let v1 = e1.value.as_ref().unwrap().clone();
                                    match v0 * v1 {
                                        Ok(v) => {
                                            e.value = Some(v);
                                            Ok(true)
                                        },
                                        Err(_) => {
                                            eprintln!
                                                ("error: {}: integer overflow in constant multiplication expression",
                                                 item_name);
                                            Err(())
                                        }
                                    }
                                },
                                Ok(false) => Ok(false),
                                Err(_) => r[1],
                            }
                        },
                        Ok(false) => {
                            match r[1] {
                                Ok(_) => Ok(false),
                                Err(_) => r[1],
                            }
                        },
                        Err(_) => r[0],
                    }
                },
                ExprOp::LShift(e0, e1) => {
                    match r[0] {
                        Ok(true) => {
                            match r[1] {
                                Ok(true) => {
                                    let v0 = e0.value.as_ref().unwrap().clone();
                                    let v1 = e1.value.as_ref().unwrap().clone();
                                    match v0 << v1 {
                                        Ok(v) => {
                                            e.value = Some(v);
                                            Ok(true)
                                        },
                                        Err(_) => {
                                            eprintln!("error: {}: integer overflow in constant lshift expression",
                                                      item_name);
                                            Err(())
                                        }
                                    }
                                },
                                Ok(false) => Ok(false),
                                Err(_) => r[1],
                            }
                        },
                        Ok(false) => {
                            match r[1] {
                                Ok(_) => Ok(false),
                                Err(_) => r[1],
                            }
                        },
                        Err(_) => r[0],
                    }
                }
            }
        })
    }

    fn try_eval_value_range(&self, item_name: &str, r: &mut ValueRange) -> Result<bool, ()> {
        match r {
            ValueRange::Range {
                min_value,
                max_value,
            } => {
                if let Some(min_value) = min_value {
                    if !self.try_eval_expr(item_name, min_value)? {
                        return Ok(false);
                    }
                }
                if let Some(max_value) = max_value {
                    if !self.try_eval_expr(item_name, max_value)? {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            ValueRange::Discrete(values) => {
                for v in values.iter_mut() {
                    if !self.try_eval_expr(item_name, v)? {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
        }
    }

    fn structure_plain_member_type_size(
        &self,
        table_name: &str,
        member_name: &str,
        member_type: &StructureTableEntryResolvedBaseType,
    ) -> Result<Option<(ExprValue, ExprValue)>, io::Error> {
        match member_type {
            StructureTableEntryResolvedBaseType::Predefined(predefined) => {
                let size = ExprValue::from(predefined.bits / 8);
                let max_size = size.clone();
                Ok(Some((max_size, size)))
            }
            StructureTableEntryResolvedBaseType::Constants(index) => {
                let constants = self.get_constants(*index);
                match &constants.size {
                    Some(size) => {
                        let size = size.clone();
                        let max_size = size.clone();
                        Ok(Some((max_size, size)))
                    }
                    None => {
                        eprintln!(
                            "error: {}: member {} is of constant type without base",
                            table_name, member_name
                        );
                        Err(io::Error::from(io::ErrorKind::InvalidData))
                    }
                }
            }
            StructureTableEntryResolvedBaseType::Bits(index) => {
                let size = self.get_bits(*index).size.as_ref().unwrap().clone();
                let max_size = size.clone();
                Ok(Some((max_size, size)))
            }
            StructureTableEntryResolvedBaseType::Type(index) => {
                let size = self.get_type(*index).size.as_ref().unwrap().clone();
                let max_size = size.clone();
                Ok(Some((max_size, size)))
            }
            StructureTableEntryResolvedBaseType::Structure(index) => {
                let s = self.get_structure(*index);
                match &s.max_size {
                    Some(max_size) => {
                        let size = s.size.as_ref().unwrap().clone();
                        Ok(Some((max_size.clone(), size)))
                    }
                    None => Ok(None),
                }
            }
        }
    }

    fn check_runtime_const_recursion(&self) -> Result<(), io::Error> {
        // Runtime constant values can depend on the sizeof() of defined
        // structures/unions and vice-versa.  Check there are not circular
        // dependencies to ensure there won't be any infinite recursions at
        // runtime.
        struct WalkStackEntry {
            index: StructuresPartTablesIndex,
            runtime_const_deps: Vec<PredefinedConstantRef>,
            cur_runtime_const_dep: usize,
            next_runtime_const_sizeof_dep: usize,
        }

        for i in self.iter() {
            let mut walk_stack: Vec<WalkStackEntry> = Vec::new();
            let enter_structure = |walk_stack: &mut Vec<WalkStackEntry>,
                                   index: StructuresPartTablesStructureIndex|
             -> Result<(), io::Error> {
                let table = self.get_structure(index);
                match table.max_size.as_ref().unwrap() {
                    ExprValue::RuntimeConstant(runtime_const_deps)
                    | ExprValue::DynamicWithRuntimeConstantDep(runtime_const_deps) => {
                        let index = StructuresPartTablesIndex::Structure(index);
                        if walk_stack.iter().any(|entry| entry.index == index) {
                            eprintln!(
                                "error: {}: sizeof() recursion through the runtime constants",
                                &table.name
                            );
                            return Err(io::Error::from(io::ErrorKind::InvalidData));
                        }
                        let runtime_const_deps: Vec<PredefinedConstantRef> = runtime_const_deps
                            .iter()
                            .filter_map(|predefined| predefined.sizeof_deps.map(|_| *predefined))
                            .collect();
                        if !runtime_const_deps.is_empty() {
                            walk_stack.push(WalkStackEntry {
                                index,
                                runtime_const_deps,
                                cur_runtime_const_dep: 0,
                                next_runtime_const_sizeof_dep: 0,
                            });
                        }
                    }
                    _ => (),
                };
                Ok(())
            };
            let enter_union = |walk_stack: &mut Vec<WalkStackEntry>,
                               index: StructuresPartTablesUnionIndex|
             -> Result<(), io::Error> {
                let table = self.get_union(index);
                match table.max_size.as_ref().unwrap() {
                    ExprValue::RuntimeConstant(runtime_const_deps)
                    | ExprValue::DynamicWithRuntimeConstantDep(runtime_const_deps) => {
                        let index = StructuresPartTablesIndex::Union(index);
                        if walk_stack.iter().any(|entry| entry.index == index) {
                            eprintln!(
                                "error: {}: sizeof() recursion through the runtime constants",
                                &table.name
                            );
                            return Err(io::Error::from(io::ErrorKind::InvalidData));
                        }
                        let runtime_const_deps: Vec<PredefinedConstantRef> = runtime_const_deps
                            .iter()
                            .filter_map(|predefined| predefined.sizeof_deps.map(|_| *predefined))
                            .collect();
                        if !runtime_const_deps.is_empty() {
                            walk_stack.push(WalkStackEntry {
                                index,
                                runtime_const_deps,
                                cur_runtime_const_dep: 0,
                                next_runtime_const_sizeof_dep: 0,
                            });
                        }
                    }
                    _ => (),
                };
                Ok(())
            };

            match i {
                StructuresPartTablesIndex::Structure(index) => {
                    enter_structure(&mut walk_stack, index)?
                }
                StructuresPartTablesIndex::Union(index) => enter_union(&mut walk_stack, index)?,
                _ => (),
            };
            while !walk_stack.is_empty() {
                let top = walk_stack.last_mut().unwrap();
                assert_ne!(top.cur_runtime_const_dep, top.runtime_const_deps.len());
                while top.cur_runtime_const_dep != top.runtime_const_deps.len()
                    && (top.next_runtime_const_sizeof_dep
                        == top.runtime_const_deps[top.cur_runtime_const_dep]
                            .sizeof_deps
                            .unwrap()
                            .len())
                {
                    top.cur_runtime_const_dep += 1;
                    top.next_runtime_const_sizeof_dep = 0;
                }
                if top.cur_runtime_const_dep == top.runtime_const_deps.len() {
                    walk_stack.pop();
                    continue;
                }

                let cur_runtime_const_dep = top.runtime_const_deps[top.cur_runtime_const_dep];
                let sizeof_dep =
                    cur_runtime_const_dep.sizeof_deps.unwrap()[top.next_runtime_const_sizeof_dep];
                top.next_runtime_const_sizeof_dep += 1;

                let sizeof_dep = self.translate_aliases(sizeof_dep);
                let index = self.lookup(&sizeof_dep);
                match index {
                    Some(StructuresPartTablesIndex::Structure(index)) => {
                        let table = self.get_structure(index);
                        match table.max_size.as_ref().unwrap() {
                            ExprValue::Dynamic | ExprValue::DynamicWithRuntimeConstantDep(_) => {
                                eprintln!
                                    ("error: sizeof() dependency \"{}\" of runtime constant \"{}\" has dynamic size",
                                     &sizeof_dep as &str, cur_runtime_const_dep.name);
                                return Err(io::Error::from(io::ErrorKind::InvalidData));
                            }
                            _ => (),
                        };
                        enter_structure(&mut walk_stack, index)?;
                    }
                    Some(StructuresPartTablesIndex::Union(index)) => {
                        let table = self.get_union(index);
                        match table.max_size.as_ref().unwrap() {
                            ExprValue::Dynamic | ExprValue::DynamicWithRuntimeConstantDep(_) => {
                                eprintln!
                                    ("error: sizeof() dependency \"{}\" of runtime constant \"{}\" has dynamic size",
                                     &sizeof_dep as &str, cur_runtime_const_dep.name);
                                return Err(io::Error::from(io::ErrorKind::InvalidData));
                            }
                            _ => (),
                        };
                        enter_union(&mut walk_stack, index)?;
                    }
                    Some(StructuresPartTablesIndex::Constants(index)) => {
                        let table = self.get_constants(index);
                        if table.resolved_base.is_none() {
                            eprintln!
                                ("error: dependency \"{}\" of runtime constant \"{}\" on constants type with no base",
                                 &sizeof_dep as &str, cur_runtime_const_dep.name);
                            return Err(io::Error::from(io::ErrorKind::InvalidData));
                        }
                    }
                    Some(_) => (),
                    None => {
                        if PredefinedTypes::lookup(&sizeof_dep).is_none() {
                            eprintln!("error: sizeof() dependency \"{}\" of runtime constant \"{}\" not found",
                                      &sizeof_dep as &str, cur_runtime_const_dep.name);
                            return Err(io::Error::from(io::ErrorKind::InvalidData));
                        }
                    }
                };
            }
        }

        Ok(())
    }

    pub(in super::super::super) fn eval_all(&mut self) -> Result<(), io::Error> {
        // Constant values, structure + union sizes can depend on each other
        // through sizeof() expressions and nesting of
        // structures/unions. Evaluate those first, erroring out if theirs some
        // circular dependency.
        let mut consts_worklist = Vec::new();
        let mut structures_worklist = Vec::new();
        let mut unions_worklist = Vec::new();
        for i in self.iter() {
            match i {
                StructuresPartTablesIndex::Constants(i) => {
                    let mut table = self.get_constants_mut(i);
                    if let Some(underlying_type) = table.resolved_base {
                        table.size = Some(ExprValue::from(underlying_type.bits / 8));
                    }

                    for j in 0..table.entries.len() {
                        consts_worklist.push(StructuresPartTablesConstantIndex(i, j));
                    }
                }
                StructuresPartTablesIndex::Bits(i) => {
                    let mut table = self.get_bits_mut(i);
                    let base = table.resolved_base.unwrap();
                    let underlying_type =
                        self.find_type_table_underlying_type(&table.name, base)?;
                    table.underlying_type = Some(underlying_type);
                    table.size = Some(ExprValue::from(underlying_type.bits / 8));
                }
                StructuresPartTablesIndex::Type(i) => {
                    let mut table = self.get_type_mut(i);
                    let base = table.resolved_base.unwrap();
                    let underlying_type =
                        self.find_type_table_underlying_type(&table.name, base)?;
                    table.underlying_type = Some(underlying_type);
                    table.size = Some(ExprValue::from(underlying_type.bits / 8));
                }
                StructuresPartTablesIndex::Structure(i) => {
                    structures_worklist.push(i);
                }
                StructuresPartTablesIndex::Union(i) => {
                    unions_worklist.push(i);
                }
                StructuresPartTablesIndex::Aliases(_) => {}
            }
        }

        let mut evaluated_some = true;
        while evaluated_some {
            evaluated_some = false;

            let mut wl = std::mem::take(&mut consts_worklist);
            for i in wl.drain(..) {
                // Evaluation of constants might need to lookup other constants
                // and hence, ultimately might need to take a borrow on the very
                // same constants table. Evaluate a copy of the value
                // expression and assign it back once done.
                let c = self.get_constant(i);
                let mut value = c.value.clone();
                if self
                    .try_eval_expr(&c.name, &mut value)
                    .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?
                {
                    match value.value.as_ref().unwrap() {
                        ExprValue::CompiletimeConstant(_) => (),
                        ExprValue::RuntimeConstant(_) => (),
                        ExprValue::Dynamic | ExprValue::DynamicWithRuntimeConstantDep(_) => {
                            eprintln!("error: {}: expression is not constant", &c.name);
                            return Err(io::Error::from(io::ErrorKind::InvalidData));
                        }
                    }
                    drop(c);
                    let mut c = self.get_constant_mut(i);
                    c.value = value;
                    evaluated_some = true;
                } else {
                    consts_worklist.push(i);
                }
            }

            let mut wl = std::mem::take(&mut structures_worklist);
            'work_items: for i in wl.drain(..) {
                let mut structure_max_size = ExprValue::from(0u32);
                let mut structure_size = ExprValue::from(0u32);
                let mut j: usize = 0;
                'reborrow: loop {
                    let table = self.get_structure(i);
                    while j < table.entries.len() {
                        let entry = &table.entries[j];
                        let member_size = match &entry.entry_type {
                            StructureTableEntryType::Plain(plain_type) => {
                                let base_type = plain_type.resolved_base_type.as_ref().unwrap();
                                self.structure_plain_member_type_size(
                                    &table.name,
                                    &entry.name,
                                    base_type,
                                )?
                            }
                            StructureTableEntryType::Discriminant(discriminant_type) => {
                                let discriminant_type =
                                    discriminant_type.resolved_discriminant_type.unwrap();
                                let discriminant_type =
                                    StructureTableEntryResolvedBaseType::from(discriminant_type);
                                self.structure_plain_member_type_size(
                                    &table.name,
                                    &entry.name,
                                    &discriminant_type,
                                )?
                            }
                            StructureTableEntryType::Union(union_type) => {
                                let union_type =
                                    self.get_union(union_type.resolved_union_type.unwrap());
                                match &union_type.max_size {
                                    Some(max_size) => {
                                        let size = union_type.size.as_ref().unwrap().clone();
                                        Some((max_size.clone(), size))
                                    }
                                    None => None,
                                }
                            }
                            StructureTableEntryType::Array(array_type) => {
                                let element_type =
                                    array_type.resolved_element_type.as_ref().unwrap();
                                let element_size = self.structure_plain_member_type_size(
                                    &table.name,
                                    &entry.name,
                                    element_type,
                                )?;
                                let (element_max_size, element_size) = match element_size {
                                    Some(element_size) => element_size,
                                    None => {
                                        structures_worklist.push(i);
                                        continue 'work_items;
                                    }
                                };

                                let (array_max_size, array_size) = match &array_type.size.value {
                                    Some(array_size) => match &array_type.size_range {
                                        Some(ValueRange::Range {
                                            min_value: _,
                                            max_value,
                                        }) => {
                                            if let Some(max_value) = max_value {
                                                (max_value.value.as_ref().unwrap(), array_size)
                                            } else {
                                                (array_size, array_size)
                                            }
                                        }
                                        _ => (array_size, array_size),
                                    },
                                    None => {
                                        let mut array_size = array_type.size.clone();
                                        if !self
                                            .try_eval_expr(&entry.name, &mut array_size)
                                            .map_err(|_| {
                                                io::Error::from(io::ErrorKind::InvalidData)
                                            })?
                                        {
                                            structures_worklist.push(i);
                                            continue 'work_items;
                                        }
                                        let array_size_range = match &array_type.size_range {
                                            Some(range) => {
                                                let mut range = range.clone();
                                                if !self
                                                    .try_eval_value_range(&entry.name, &mut range)
                                                    .map_err(|_| {
                                                        io::Error::from(io::ErrorKind::InvalidData)
                                                    })?
                                                {
                                                    structures_worklist.push(i);
                                                    continue 'work_items;
                                                }
                                                Some(range)
                                            }
                                            None => None,
                                        };
                                        drop(table);
                                        let mut table = self.get_structure_mut(i);
                                        if let StructureTableEntryType::Array(array_type) =
                                            &mut table.entries[j].entry_type
                                        {
                                            array_type.size = array_size;
                                            array_type.size_range = array_size_range;
                                        } else {
                                            unreachable!();
                                        }
                                        continue 'reborrow;
                                    }
                                };

                                let member_max_size = element_max_size * array_max_size.clone();
                                let member_max_size = match member_max_size {
                                    Ok(member_size) => member_size,
                                    Err(_) => {
                                        eprintln!(
                                            "error: {}: integer overflow in \"{}\" array size",
                                            &table.name, &entry.name
                                        );
                                        return Err(io::Error::from(io::ErrorKind::InvalidData));
                                    }
                                };

                                let member_size = element_size * array_size.clone();
                                let member_size = match member_size {
                                    Ok(member_size) => member_size,
                                    Err(_) => {
                                        eprintln!(
                                            "error: {}: integer overflow in \"{}\" array size",
                                            &table.name, &entry.name
                                        );
                                        return Err(io::Error::from(io::ErrorKind::InvalidData));
                                    }
                                };

                                Some((member_max_size, member_size))
                            }
                        };

                        match member_size {
                            Some((member_max_size, member_size)) => {
                                let size = structure_max_size + member_max_size;
                                match size {
                                    Ok(size) => structure_max_size = size,
                                    Err(_) => {
                                        eprintln!(
                                            "error: {}: integer overflow in structure size",
                                            &table.name
                                        );
                                        return Err(io::Error::from(io::ErrorKind::InvalidData));
                                    }
                                };

                                let size = structure_size + member_size;
                                match size {
                                    Ok(size) => structure_size = size,
                                    Err(_) => {
                                        eprintln!(
                                            "error: {}: integer overflow in structure size",
                                            &table.name
                                        );
                                        return Err(io::Error::from(io::ErrorKind::InvalidData));
                                    }
                                };
                            }
                            None => {
                                structures_worklist.push(i);
                                continue 'work_items;
                            }
                        };
                        j += 1;
                    }
                    break;
                }

                let mut table = self.get_structure_mut(i);
                table.max_size = Some(structure_max_size);
                table.size = Some(structure_size);
                evaluated_some = true;
            }

            let mut wl = std::mem::take(&mut unions_worklist);
            'work_items: for i in wl.drain(..) {
                let mut union_max_size = ExprValue::from(0u32);
                let mut union_size = ExprValue::Dynamic;
                let mut j: usize = 0;
                'reborrow: loop {
                    let table = self.get_union(i);
                    while j < table.entries.len() {
                        let entry = &table.entries[j];
                        let member_size = match &entry.entry_type {
                            UnionTableEntryType::Plain(plain_type) => {
                                match plain_type.resolved_base_type.as_ref() {
                                    Some(base_type) => self.structure_plain_member_type_size(
                                        &table.name,
                                        &entry.name,
                                        base_type,
                                    )?,
                                    None => Some((ExprValue::from(0u32), ExprValue::from(0u32))),
                                }
                            }
                            UnionTableEntryType::Array(array_type) => {
                                let element_type =
                                    array_type.resolved_element_type.as_ref().unwrap();
                                let element_size = self.structure_plain_member_type_size(
                                    &table.name,
                                    &entry.name,
                                    element_type,
                                )?;
                                let (element_max_size, element_size) = match element_size {
                                    Some(element_size) => element_size,
                                    None => {
                                        unions_worklist.push(i);
                                        continue 'work_items;
                                    }
                                };

                                let array_size = match &array_type.size.value {
                                    Some(array_size) => array_size,
                                    None => {
                                        let mut array_size = array_type.size.clone();
                                        if !self
                                            .try_eval_expr(&entry.name, &mut array_size)
                                            .map_err(|_| {
                                                io::Error::from(io::ErrorKind::InvalidData)
                                            })?
                                        {
                                            unions_worklist.push(i);
                                            continue 'work_items;
                                        }
                                        match &array_size.value {
                                            Some(ExprValue::Dynamic)
                                            | Some(ExprValue::DynamicWithRuntimeConstantDep(_)) => {
                                                eprintln!(
                                                    "error: {}: array size of \"{}\" not constant",
                                                    &table.name, &entry.name
                                                );
                                                return Err(io::Error::from(
                                                    io::ErrorKind::InvalidData,
                                                ));
                                            }
                                            _ => (),
                                        };

                                        drop(table);
                                        let mut table = self.get_union_mut(i);
                                        if let UnionTableEntryType::Array(array_type) =
                                            &mut table.entries[j].entry_type
                                        {
                                            array_type.size = array_size;
                                        } else {
                                            unreachable!();
                                        }
                                        continue 'reborrow;
                                    }
                                };

                                let member_max_size = element_max_size * array_size.clone();
                                let member_max_size = match member_max_size {
                                    Ok(member_size) => member_size,
                                    Err(_) => {
                                        eprintln!(
                                            "error: {}: integer overflow in \"{}\" array size",
                                            &table.name, &entry.name
                                        );
                                        return Err(io::Error::from(io::ErrorKind::InvalidData));
                                    }
                                };

                                let member_size = element_size * array_size.clone();
                                let member_size = match member_size {
                                    Ok(member_size) => member_size,
                                    Err(_) => {
                                        eprintln!(
                                            "error: {}: integer overflow in \"{}\" array size",
                                            &table.name, &entry.name
                                        );
                                        return Err(io::Error::from(io::ErrorKind::InvalidData));
                                    }
                                };

                                Some((member_max_size, member_size))
                            }
                        };

                        match member_size {
                            Some((member_max_size, member_size)) => {
                                union_max_size = ExprValue::max(union_max_size, member_max_size);
                                union_size = ExprValue::max(union_size, member_size);
                            }
                            None => {
                                unions_worklist.push(i);
                                continue 'work_items;
                            }
                        };
                        j += 1;
                    }
                    break;
                }

                let mut table = self.get_union_mut(i);
                table.max_size = Some(union_max_size);
                table.size = Some(union_size);
                evaluated_some = true;
            }
        }

        assert!(
            consts_worklist.is_empty()
                || !structures_worklist.is_empty()
                || !unions_worklist.is_empty()
        );
        if !structures_worklist.is_empty() {
            let table = self.get_structure(structures_worklist[0]);
            eprintln!(
                "error: {}: failed to calculate structure size due to some circular dependency",
                &table.name
            );
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        } else if !unions_worklist.is_empty() {
            let table = self.get_union(unions_worklist[0]);
            eprintln!(
                "error: {}: failed to calculate union size due to some circular dependency",
                &table.name
            );
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }

        // Before moving on, check that there are no recursions between sizeof()
        // expressions and the runtime constants.
        self.check_runtime_const_recursion()?;

        // Evaluate the rest.
        for i in self.iter() {
            match i {
                StructuresPartTablesIndex::Bits(index) => {
                    let table = self.get_bits_mut(index);
                    let base_type = *table.get_underlying_type();
                    let (table_name, mut entries) =
                        RefMut::map_split(table, |table| (&mut table.name, &mut table.entries));
                    for entry in entries.iter_mut() {
                        let evaluated = self
                            .try_eval_expr(&table_name, &mut entry.bits.min_bit_index)
                            .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
                        assert!(evaluated);
                        match entry.bits.min_bit_index.value.as_ref().unwrap() {
                            ExprValue::CompiletimeConstant(b) => {
                                if b.value < 0i128 || b.value >= base_type.bits as i128 {
                                    eprintln!(
                                        "error: {}: {}'s bit range out of bounds",
                                        &table_name, &entry.name
                                    );
                                    return Err(io::Error::from(io::ErrorKind::InvalidData));
                                }
                            }
                            _ => {
                                eprintln!(
                                    "error: {}: {}'s bit range not a compiletime constant",
                                    &table_name, &entry.name
                                );
                                return Err(io::Error::from(io::ErrorKind::InvalidData));
                            }
                        };

                        if let Some(max_bit_index) = &mut entry.bits.max_bit_index {
                            let evaluated = self
                                .try_eval_expr(&table_name, max_bit_index)
                                .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
                            assert!(evaluated);
                            match max_bit_index.value.as_ref().unwrap() {
                                ExprValue::CompiletimeConstant(b) => {
                                    if b.value < 0i128 || b.value >= base_type.bits as i128 {
                                        eprintln!(
                                            "error: {}: {}'s bit range out of bounds",
                                            &table_name, &entry.name
                                        );
                                        return Err(io::Error::from(io::ErrorKind::InvalidData));
                                    }
                                }
                                _ => {
                                    eprintln!(
                                        "error: {}: {}'s bit range not a compiletime constant",
                                        &table_name, &entry.name
                                    );
                                    return Err(io::Error::from(io::ErrorKind::InvalidData));
                                }
                            };
                        }
                    }
                    drop(table_name);
                    drop(entries);
                    let table = self.get_bits_mut(index);
                    let (table_name, mut reserved) =
                        RefMut::map_split(table, |table| (&mut table.name, &mut table.reserved));
                    for reserved in reserved.iter_mut() {
                        let evaluated = self
                            .try_eval_expr(&table_name, &mut reserved.min_bit_index)
                            .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
                        assert!(evaluated);
                        match reserved.min_bit_index.value.as_ref().unwrap() {
                            ExprValue::CompiletimeConstant(b) => {
                                if b.value < 0i128 || b.value >= base_type.bits as i128 {
                                    eprintln!(
                                        "error: {}: reserved bit range out of bounds",
                                        &table_name
                                    );
                                    return Err(io::Error::from(io::ErrorKind::InvalidData));
                                }
                            }
                            _ => {
                                eprintln!(
                                    "error: {}: reserved bit range not a compiletime constant",
                                    &table_name
                                );
                                return Err(io::Error::from(io::ErrorKind::InvalidData));
                            }
                        };

                        if let Some(max_bit_index) = &mut reserved.max_bit_index {
                            let evaluated = self
                                .try_eval_expr(&table_name, max_bit_index)
                                .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
                            assert!(evaluated);
                            match max_bit_index.value.as_ref().unwrap() {
                                ExprValue::CompiletimeConstant(b) => {
                                    if b.value < 0i128 || b.value >= base_type.bits as i128 {
                                        eprintln!(
                                            "error: {}: reserved bit range out of bounds",
                                            &table_name
                                        );
                                        return Err(io::Error::from(io::ErrorKind::InvalidData));
                                    }
                                }
                                _ => {
                                    eprintln!(
                                        "error: {}: reserved bit range not a compiletime constant",
                                        &table_name
                                    );
                                    return Err(io::Error::from(io::ErrorKind::InvalidData));
                                }
                            };
                        }
                    }
                }
                StructuresPartTablesIndex::Type(index) => {
                    let table = self.get_type_mut(index);
                    let mut enum_like = table.enum_like;
                    let (table_name, mut entries) =
                        RefMut::map_split(table, |table| (&mut table.name, &mut table.entries));
                    for entry in entries.iter_mut() {
                        let evaluated = self
                            .try_eval_value_range(&table_name, &mut entry.values)
                            .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
                        assert!(evaluated);
                    }
                    drop(table_name);
                    drop(entries);

                    // If marked enum-like, i.e. still being considered as a
                    // potential union discriminator at this point, reevaluate
                    // this assessment: all values must be associated with compile-time
                    // constants and be distinct.
                    if !enum_like {
                        continue;
                    }
                    let table = self.get_type(index);
                    for j in 0..table.entries.len() {
                        let entry = match &table.entries[j].values {
                            ValueRange::Discrete(values) => &values[0],
                            _ => unreachable!(),
                        };
                        match entry.op {
                            ExprOp::Id(_) => (),
                            _ => unreachable!(),
                        };
                        match entry.value.as_ref().unwrap() {
                            ExprValue::CompiletimeConstant(value) => {
                                for k in 0..table.entries.len() {
                                    if k == j {
                                        continue;
                                    }

                                    let other = match &table.entries[k].values {
                                        ValueRange::Discrete(values) => &values[0],
                                        _ => unreachable!(),
                                    };
                                    match other.value.as_ref().unwrap() {
                                        ExprValue::CompiletimeConstant(other_value) => {
                                            if value == other_value {
                                                enum_like = false;
                                                break;
                                            }
                                        }
                                        _ => {
                                            enum_like = false;
                                            break;
                                        }
                                    };
                                }
                                if !enum_like {
                                    break;
                                }
                            }
                            _ => {
                                enum_like = false;
                                break;
                            }
                        };
                    }
                    if !enum_like {
                        drop(table);
                        let mut table = self.get_type_mut(index);
                        table.enum_like = false;
                    } else {
                    }
                }
                StructuresPartTablesIndex::Constants(index) => {
                    // In Constants tables, there sometimes are "helper" constants like
                    // "TPM_CC_FIRST" whose value equals some of the other "real"
                    // members. There is going to be a conflict if the Constants happens to
                    // be used as a union discriminator. Find the conflicting helpers and
                    // mark them as such.
                    let mut enum_like = true;
                    let mut j = 0;
                    'reborrow: loop {
                        let table = self.get_constants(index);
                        let entries = &table.entries;
                        while j < entries.len() {
                            let entry = &entries[j];
                            match entry.value.value.as_ref().unwrap() {
                                ExprValue::CompiletimeConstant(value) => {
                                    for (k, other) in entries.iter().enumerate() {
                                        if j == k {
                                            continue;
                                        }
                                        if let ExprValue::CompiletimeConstant(other_value) =
                                            other.value.value.as_ref().unwrap()
                                        {
                                            if value != other_value {
                                                continue;
                                            }

                                            let maybe_helper = |name: &str| -> bool {
                                                // Apply some heuristics on the constant's name for determining
                                                // whether it might be an internal helper value.
                                                name.ends_with("_FIRST")
                                                    || name.ends_with("_LAST")
                                                    || !name.starts_with(&table.name)
                                            };

                                            if entry.deps.conflicts_with(&other.deps) {
                                                // Ok, the two constants won't be enabled at the same time.
                                            } else if maybe_helper(&entry.name) {
                                                drop(table);
                                                let mut table = self.get_constants_mut(index);
                                                let entry = &mut table.entries[j];
                                                entry.is_helper_duplicate = true;
                                                j += 1;
                                                continue 'reborrow;
                                            } else if !maybe_helper(&other.name) {
                                                enum_like = false;
                                            }
                                        }
                                    }
                                }
                                _ => {
                                    // Not a Compile-time constant, cannot be used as an union discriminator.
                                    enum_like = false;
                                }
                            };

                            j += 1;
                        }
                        break;
                    }

                    if !enum_like {
                        let mut table = self.get_constants_mut(index);
                        table.enum_like = false;
                        // Undo the ->is_helper_duplicate setting from above.
                        for entry in &mut table.entries {
                            entry.is_helper_duplicate = false;
                        }
                    }
                }
                StructuresPartTablesIndex::Structure(index) => {
                    let table = self.get_structure_mut(index);
                    let (table_name, mut entries) =
                        RefMut::map_split(table, |table| (&mut table.name, &mut table.entries));
                    for entry in entries.iter_mut() {
                        if let StructureTableEntryType::Plain(plain_type) = &mut entry.entry_type {
                            if let Some(range) = &mut plain_type.range {
                                let evaluated = self
                                    .try_eval_value_range(&table_name, range)
                                    .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
                                assert!(evaluated);
                            }
                        }
                    }
                }
                _ => (),
            };
        }

        // Finally, as we now have classified Constants + Type tables as
        // enum-like or not, and sorted out helper duplicates,
        // verify all union discriminants are valid.
        for index in self.iter() {
            let index = match index {
                StructuresPartTablesIndex::Structure(index) => index,
                _ => continue,
            };

            let mut table = self.get_structure_mut(index);
            for j in 0..table.entries.len() {
                let entry = &table.entries[j];
                let discriminant_type = match &entry.entry_type {
                    StructureTableEntryType::Discriminant(discriminant_type) => discriminant_type,
                    _ => continue,
                };
                let conditional = discriminant_type.discriminant_type_conditional
                    || discriminant_type.discriminant_type_enable_conditional;
                match discriminant_type.resolved_discriminant_type.unwrap() {
                    StructureTableEntryResolvedDiscriminantType::Constants(index) => {
                        let discriminant_table = self.get_constants(index);
                        if !discriminant_table.enum_like {
                            eprintln!("error: {}: {}: non-enum-like constants \"{}\" used as union discriminator",
                                      &table.name, &entry.name, &discriminant_table.name);
                            return Err(io::Error::from(io::ErrorKind::InvalidData));
                        }
                    }
                    StructureTableEntryResolvedDiscriminantType::Type(index) => {
                        let discriminant_table = self.get_type(index);
                        if !discriminant_table.enum_like {
                            eprintln!("error: {}: {}: non-enum-like type \"{}\" used as union discriminator",
                                      &table.name, &entry.name, &discriminant_table.name);
                            return Err(io::Error::from(io::ErrorKind::InvalidData));
                        }
                    }
                };

                // Track whether or not the conditional selector, if any, selects the empty type
                // ("void") in all unions associated with the discriminant. The discriminant and
                // associated union members will be stored in a dedicated "tagged union"
                // structure. In case the conditional selector, if any, selects an empty "void"-like
                // field in each associated union, it doesn't necessarily need a representation in
                // the tagged union itself -- all instances thereof could get wrapped in e.g. a Rust
                // Option<> instead. This potentially helps to avoids duplicated tagged union types
                // which differ only in the conditional member and also, allows more a more natural
                // mapping to language specific idioms.
                let mut conditional_selects_none = conditional;
                let mut nconditional_selectors = 0;
                let selectors = UnionSelectorIterator::new(
                    self,
                    discriminant_type.resolved_discriminant_type.unwrap(),
                    conditional,
                );
                for selector in selectors {
                    // If there's more than one conditional entry in the discriminant type, the
                    // conditional selectors all need an explicit representation in the tagged union
                    // itself for unambiguity.
                    let selector_is_conditional = selector.is_conditional();
                    if selector_is_conditional {
                        nconditional_selectors += 1;
                        if nconditional_selectors > 1 {
                            if discriminant_type.discriminant_type_conditional {
                                eprintln!
                                ("error: {}: {}: multiple conditional entries in conditional union discriminant",
                                 &table.name, &entry.name);
                                return Err(io::Error::from(io::ErrorKind::InvalidData));
                            }
                            conditional_selects_none = false;
                        }
                    }
                    for union_member_index in discriminant_type.discriminated_union_members.iter() {
                        let union_member_entry = &table.entries[*union_member_index];
                        if !matches!(
                            selector.config_deps().partial_cmp(&union_member_entry.deps),
                            Some(cmp::Ordering::Less | cmp::Ordering::Equal)
                        ) {
                            eprintln!
                                ("error: {}: {}: union member config dependencies too weak for \"{}\"",
                                 &table.name, &entry.name, selector.name());
                            return Err(io::Error::from(io::ErrorKind::InvalidData));
                        }
                        let union_member_entry_type = match &union_member_entry.entry_type {
                            StructureTableEntryType::Union(union_member_entry_type) => {
                                union_member_entry_type
                            }
                            _ => unreachable!(),
                        };
                        let union_type = union_member_entry_type.resolved_union_type.unwrap();
                        let union_type = self.get_union(union_type);
                        let selected_union_entry = match union_type.lookup_member(selector.name()) {
                            Some(k) => k,
                            None => {
                                eprintln!(
                                    "error: {}: {}: no entry for selector \"{}\" in union \"{}\"",
                                    &table.name,
                                    &entry.name,
                                    selector.name(),
                                    &union_type.name
                                );
                                return Err(io::Error::from(io::ErrorKind::InvalidData));
                            }
                        };

                        if conditional_selects_none && selector_is_conditional {
                            let selected_union_entry = &union_type.entries[selected_union_entry];
                            match &selected_union_entry.entry_type {
                                UnionTableEntryType::Plain(plain_type) => {
                                    if plain_type.base_type.is_some() {
                                        conditional_selects_none = false;
                                    }
                                }
                                UnionTableEntryType::Array(_) => {
                                    conditional_selects_none = false;
                                }
                            };

                            if !conditional_selects_none
                                && discriminant_type.discriminant_type_conditional
                            {
                                eprintln!
                                    ("error: {}: {}: conditional selector \"{}\" selects non-trivial union field",
                                     &table.name, &entry.name, selector.name());
                                return Err(io::Error::from(io::ErrorKind::InvalidData));
                            }
                        }
                    }
                }

                if conditional_selects_none {
                    let entry = &mut table.entries[j];
                    match &mut entry.entry_type {
                        StructureTableEntryType::Discriminant(discriminant_type) => {
                            discriminant_type.conditional_selects_none = true;
                        }
                        _ => unreachable!(),
                    }
                }
            }
        }

        Ok(())
    }
}
