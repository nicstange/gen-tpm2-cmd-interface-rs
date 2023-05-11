// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

use super::predefined::{PredefinedConstantRef, PredefinedTypeRef};
use super::string_transformer::StringTransformer;
use super::tables::{StructuresPartTablesConstantIndex, StructuresPartTablesIndex};
use std::cmp;
use std::collections::HashSet;
use std::iter::Iterator;
use std::ops;

#[derive(Clone, Debug)]
pub struct ExprId {
    pub name: String,
    pub resolved: Option<ExprResolvedId>,
}

impl ExprId {
    fn new(name: String) -> Self {
        Self {
            name,
            resolved: None,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum ExprResolvedId {
    PredefinedConstant(PredefinedConstantRef),
    Constant(StructuresPartTablesConstantIndex),
    StructMember(usize),
}

#[derive(Clone, Debug)]
pub struct ExprSizeof {
    pub name: String,
    pub resolved: Option<ExprResolvedType>,
}

impl ExprSizeof {
    fn new(name: String) -> Self {
        Self {
            name,
            resolved: None,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum ExprResolvedType {
    PredefinedType(PredefinedTypeRef),
    Type(StructuresPartTablesIndex),
}

#[derive(Clone, Debug)]
pub enum ExprOp {
    Hex(String),
    Dec(String),
    Id(ExprId),
    Sizeof(ExprSizeof),
    Add(Box<Expr>, Box<Expr>),
    Sub(Box<Expr>, Box<Expr>),
    Mul(Box<Expr>, Box<Expr>),
    LShift(Box<Expr>, Box<Expr>),
}

#[derive(Clone, Copy, PartialOrd, Ord, PartialEq, Eq, Debug)]
pub struct ExprConstValue {
    pub value: i128,
}

impl ExprConstValue {
    fn new_from_hex(value: &str) -> Result<Self, ()> {
        let value = i128::from_str_radix(&value[2..], 16).map_err(|_| ())?;
        let value = Self { value };
        if value.repr_bits() > 64 {
            return Err(());
        }
        Ok(value)
    }

    fn new_from_dec(value: &str) -> Result<Self, ()> {
        let value = value.parse().map_err(|_| ())?;
        let value = Self { value };
        if value.repr_bits() > 64 {
            return Err(());
        }
        Ok(value)
    }

    pub fn is_signed(&self) -> bool {
        self.value < 0
    }

    pub fn repr_bits(&self) -> u32 {
        match self.is_signed() {
            false => i128::BITS - self.value.leading_zeros(),
            true => i128::BITS - self.value.leading_ones() + 1,
        }
    }
}

impl From<u32> for ExprConstValue {
    fn from(value: u32) -> Self {
        Self {
            value: value as i128,
        }
    }
}

impl From<u64> for ExprConstValue {
    fn from(value: u64) -> Self {
        Self {
            value: value as i128,
        }
    }
}

impl TryFrom<i128> for ExprConstValue {
    type Error = ();

    fn try_from(value: i128) -> Result<Self, Self::Error> {
        let value = Self { value };
        if value.repr_bits() > 64 {
            Err(())
        } else {
            Ok(value)
        }
    }
}

impl ops::Add for ExprConstValue {
    type Output = Result<Self, ()>;

    fn add(self, other: ExprConstValue) -> Self::Output {
        self.value
            .checked_add(other.value)
            .map(|v| Self { value: v })
            .filter(|v| v.repr_bits() <= 64)
            .ok_or(())
    }
}

impl ops::Sub for ExprConstValue {
    type Output = Result<Self, ()>;

    fn sub(self, other: ExprConstValue) -> Self::Output {
        self.value
            .checked_sub(other.value)
            .map(|v| Self { value: v })
            .filter(|v| v.repr_bits() <= 64)
            .ok_or(())
    }
}

impl ops::Mul for ExprConstValue {
    type Output = Result<Self, ()>;

    fn mul(self, other: ExprConstValue) -> Self::Output {
        self.value
            .checked_mul(other.value)
            .map(|v| Self { value: v })
            .filter(|v| v.repr_bits() <= 64)
            .ok_or(())
    }
}

impl ops::Shl for ExprConstValue {
    type Output = Result<Self, ()>;

    fn shl(self, other: ExprConstValue) -> Self::Output {
        // Lending to C, shifting negative values to the left is UB.
        if self.value < 0
            || other.value < 0
            || other.value > u32::MAX as i128
            || i128::BITS - 1 - self.repr_bits() < other.value as u32
        {
            return Err(());
        }
        self.value
            .checked_shl(other.value as u32)
            .map(|v| Self { value: v })
            .filter(|v| v.repr_bits() <= 64)
            .ok_or(())
    }
}

#[derive(Clone, Debug)]
pub enum ExprValue {
    CompiletimeConstant(ExprConstValue),
    RuntimeConstant(HashSet<PredefinedConstantRef>), // depends on a configurable runtime limit pseudo-constant
    Dynamic,
    DynamicWithRuntimeConstantDep(HashSet<PredefinedConstantRef>), // dynamic, but also depends on some runtime limit
}

impl ExprValue {
    pub fn max(v0: ExprValue, v1: ExprValue) -> Self {
        match v0 {
            Self::CompiletimeConstant(v0) => match v1 {
                Self::CompiletimeConstant(v1) => Self::CompiletimeConstant(cmp::max(v0, v1)),
                Self::RuntimeConstant(deps) => Self::RuntimeConstant(deps),
                Self::Dynamic => Self::Dynamic,
                Self::DynamicWithRuntimeConstantDep(deps) => {
                    Self::DynamicWithRuntimeConstantDep(deps)
                }
            },
            Self::RuntimeConstant(v0_deps) => match v1 {
                Self::CompiletimeConstant(_) => Self::RuntimeConstant(v0_deps),
                Self::RuntimeConstant(v1_deps) => {
                    let mut deps = v0_deps;
                    deps.extend(&v1_deps);
                    Self::RuntimeConstant(deps)
                }
                Self::Dynamic => Self::DynamicWithRuntimeConstantDep(v0_deps),
                Self::DynamicWithRuntimeConstantDep(v1_deps) => {
                    let mut deps = v0_deps;
                    deps.extend(&v1_deps);
                    Self::DynamicWithRuntimeConstantDep(deps)
                }
            },
            Self::Dynamic => match v1 {
                Self::CompiletimeConstant(_) => Self::Dynamic,
                Self::RuntimeConstant(v1_deps) => Self::DynamicWithRuntimeConstantDep(v1_deps),
                Self::Dynamic => Self::Dynamic,
                Self::DynamicWithRuntimeConstantDep(v1_deps) => {
                    Self::DynamicWithRuntimeConstantDep(v1_deps)
                }
            },
            Self::DynamicWithRuntimeConstantDep(v0_deps) => {
                let deps = match v1 {
                    Self::CompiletimeConstant(_) | Self::Dynamic => v0_deps,
                    Self::RuntimeConstant(v1_deps)
                    | Self::DynamicWithRuntimeConstantDep(v1_deps) => {
                        let mut deps = v0_deps;
                        deps.extend(&v1_deps);
                        deps
                    }
                };
                Self::DynamicWithRuntimeConstantDep(deps)
            }
        }
    }
}

impl From<u32> for ExprValue {
    fn from(value: u32) -> Self {
        Self::CompiletimeConstant(ExprConstValue::from(value))
    }
}

impl From<u64> for ExprValue {
    fn from(value: u64) -> Self {
        Self::CompiletimeConstant(ExprConstValue::from(value))
    }
}

impl TryFrom<i128> for ExprValue {
    type Error = ();

    fn try_from(value: i128) -> Result<Self, Self::Error> {
        Ok(Self::CompiletimeConstant(ExprConstValue::try_from(value)?))
    }
}

impl ops::Add for ExprValue {
    type Output = Result<Self, ()>;

    fn add(self, other: ExprValue) -> Self::Output {
        match self {
            Self::CompiletimeConstant(v0) => match other {
                Self::CompiletimeConstant(v1) => Ok(Self::CompiletimeConstant((v0 + v1)?)),
                Self::RuntimeConstant(deps) => Ok(Self::RuntimeConstant(deps)),
                Self::Dynamic => Ok(Self::Dynamic),
                Self::DynamicWithRuntimeConstantDep(deps) => {
                    Ok(Self::DynamicWithRuntimeConstantDep(deps))
                }
            },
            Self::RuntimeConstant(v0_deps) => match other {
                Self::CompiletimeConstant(_) => Ok(Self::RuntimeConstant(v0_deps)),
                Self::RuntimeConstant(v1_deps) => {
                    let mut deps = v0_deps;
                    deps.extend(&v1_deps);
                    Ok(Self::RuntimeConstant(deps))
                }
                Self::Dynamic => Ok(Self::DynamicWithRuntimeConstantDep(v0_deps)),
                Self::DynamicWithRuntimeConstantDep(v1_deps) => {
                    let mut deps = v0_deps;
                    deps.extend(&v1_deps);
                    Ok(Self::DynamicWithRuntimeConstantDep(deps))
                }
            },
            Self::Dynamic => match other {
                Self::CompiletimeConstant(_) => Ok(Self::Dynamic),
                Self::RuntimeConstant(v1_deps) => Ok(Self::DynamicWithRuntimeConstantDep(v1_deps)),
                Self::Dynamic => Ok(Self::Dynamic),
                Self::DynamicWithRuntimeConstantDep(v1_deps) => {
                    Ok(Self::DynamicWithRuntimeConstantDep(v1_deps))
                }
            },
            Self::DynamicWithRuntimeConstantDep(v0_deps) => {
                let deps = match other {
                    Self::CompiletimeConstant(_) | Self::Dynamic => v0_deps,
                    Self::RuntimeConstant(v1_deps)
                    | Self::DynamicWithRuntimeConstantDep(v1_deps) => {
                        let mut deps = v0_deps;
                        deps.extend(&v1_deps);
                        deps
                    }
                };
                Ok(Self::DynamicWithRuntimeConstantDep(deps))
            }
        }
    }
}

impl ops::Sub for ExprValue {
    type Output = Result<Self, ()>;

    fn sub(self, other: ExprValue) -> Self::Output {
        match self {
            Self::CompiletimeConstant(v0) => match other {
                Self::CompiletimeConstant(v1) => Ok(Self::CompiletimeConstant((v0 - v1)?)),
                Self::RuntimeConstant(deps) => Ok(Self::RuntimeConstant(deps)),
                Self::Dynamic => Ok(Self::Dynamic),
                Self::DynamicWithRuntimeConstantDep(deps) => {
                    Ok(Self::DynamicWithRuntimeConstantDep(deps))
                }
            },
            Self::RuntimeConstant(v0_deps) => match other {
                Self::CompiletimeConstant(_) => Ok(Self::RuntimeConstant(v0_deps)),
                Self::RuntimeConstant(v1_deps) => {
                    let mut deps = v0_deps;
                    deps.extend(&v1_deps);
                    Ok(Self::RuntimeConstant(deps))
                }
                Self::Dynamic => Ok(Self::DynamicWithRuntimeConstantDep(v0_deps)),
                Self::DynamicWithRuntimeConstantDep(v1_deps) => {
                    let mut deps = v0_deps;
                    deps.extend(&v1_deps);
                    Ok(Self::DynamicWithRuntimeConstantDep(deps))
                }
            },
            Self::Dynamic => match other {
                Self::CompiletimeConstant(_) => Ok(Self::Dynamic),
                Self::RuntimeConstant(v1_deps) => Ok(Self::DynamicWithRuntimeConstantDep(v1_deps)),
                Self::Dynamic => Ok(Self::Dynamic),
                Self::DynamicWithRuntimeConstantDep(v1_deps) => {
                    Ok(Self::DynamicWithRuntimeConstantDep(v1_deps))
                }
            },
            Self::DynamicWithRuntimeConstantDep(v0_deps) => {
                let deps = match other {
                    Self::CompiletimeConstant(_) | Self::Dynamic => v0_deps,
                    Self::RuntimeConstant(v1_deps)
                    | Self::DynamicWithRuntimeConstantDep(v1_deps) => {
                        let mut deps = v0_deps;
                        deps.extend(&v1_deps);
                        deps
                    }
                };
                Ok(Self::DynamicWithRuntimeConstantDep(deps))
            }
        }
    }
}

impl ops::Mul for ExprValue {
    type Output = Result<Self, ()>;

    fn mul(self, other: ExprValue) -> Self::Output {
        match self {
            Self::CompiletimeConstant(v0) => match other {
                Self::CompiletimeConstant(v1) => Ok(Self::CompiletimeConstant((v0 * v1)?)),
                Self::RuntimeConstant(deps) => Ok(Self::RuntimeConstant(deps)),
                Self::Dynamic => Ok(Self::Dynamic),
                Self::DynamicWithRuntimeConstantDep(deps) => {
                    Ok(Self::DynamicWithRuntimeConstantDep(deps))
                }
            },
            Self::RuntimeConstant(v0_deps) => match other {
                Self::CompiletimeConstant(_) => Ok(Self::RuntimeConstant(v0_deps)),
                Self::RuntimeConstant(v1_deps) => {
                    let mut deps = v0_deps;
                    deps.extend(&v1_deps);
                    Ok(Self::RuntimeConstant(deps))
                }
                Self::Dynamic => Ok(Self::DynamicWithRuntimeConstantDep(v0_deps)),
                Self::DynamicWithRuntimeConstantDep(v1_deps) => {
                    let mut deps = v0_deps;
                    deps.extend(&v1_deps);
                    Ok(Self::DynamicWithRuntimeConstantDep(deps))
                }
            },
            Self::Dynamic => match other {
                Self::CompiletimeConstant(_) => Ok(Self::Dynamic),
                Self::RuntimeConstant(v1_deps) => Ok(Self::DynamicWithRuntimeConstantDep(v1_deps)),
                Self::Dynamic => Ok(Self::Dynamic),
                Self::DynamicWithRuntimeConstantDep(v1_deps) => {
                    Ok(Self::DynamicWithRuntimeConstantDep(v1_deps))
                }
            },
            Self::DynamicWithRuntimeConstantDep(v0_deps) => {
                let deps = match other {
                    Self::CompiletimeConstant(_) | Self::Dynamic => v0_deps,
                    Self::RuntimeConstant(v1_deps)
                    | Self::DynamicWithRuntimeConstantDep(v1_deps) => {
                        let mut deps = v0_deps;
                        deps.extend(&v1_deps);
                        deps
                    }
                };
                Ok(Self::DynamicWithRuntimeConstantDep(deps))
            }
        }
    }
}

impl ops::Shl for ExprValue {
    type Output = Result<Self, ()>;

    fn shl(self, other: ExprValue) -> Self::Output {
        match self {
            Self::CompiletimeConstant(v0) => match other {
                Self::CompiletimeConstant(v1) => Ok(Self::CompiletimeConstant((v0 << v1)?)),
                Self::RuntimeConstant(deps) => Ok(Self::RuntimeConstant(deps)),
                Self::Dynamic => Ok(Self::Dynamic),
                Self::DynamicWithRuntimeConstantDep(deps) => {
                    Ok(Self::DynamicWithRuntimeConstantDep(deps))
                }
            },
            Self::RuntimeConstant(v0_deps) => match other {
                Self::CompiletimeConstant(_) => Ok(Self::RuntimeConstant(v0_deps)),
                Self::RuntimeConstant(v1_deps) => {
                    let mut deps = v0_deps;
                    deps.extend(&v1_deps);
                    Ok(Self::RuntimeConstant(deps))
                }
                Self::Dynamic => Ok(Self::DynamicWithRuntimeConstantDep(v0_deps)),
                Self::DynamicWithRuntimeConstantDep(v1_deps) => {
                    let mut deps = v0_deps;
                    deps.extend(&v1_deps);
                    Ok(Self::DynamicWithRuntimeConstantDep(deps))
                }
            },
            Self::Dynamic => match other {
                Self::CompiletimeConstant(_) => Ok(Self::Dynamic),
                Self::RuntimeConstant(v1_deps) => Ok(Self::DynamicWithRuntimeConstantDep(v1_deps)),
                Self::Dynamic => Ok(Self::Dynamic),
                Self::DynamicWithRuntimeConstantDep(v1_deps) => {
                    Ok(Self::DynamicWithRuntimeConstantDep(v1_deps))
                }
            },
            Self::DynamicWithRuntimeConstantDep(v0_deps) => {
                let deps = match other {
                    Self::CompiletimeConstant(_) | Self::Dynamic => v0_deps,
                    Self::RuntimeConstant(v1_deps)
                    | Self::DynamicWithRuntimeConstantDep(v1_deps) => {
                        let mut deps = v0_deps;
                        deps.extend(&v1_deps);
                        deps
                    }
                };
                Ok(Self::DynamicWithRuntimeConstantDep(deps))
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct Expr {
    pub op: ExprOp,
    pub rdepth: usize, // Depth counting only right edges, used for eval stack slot allocation.
    pub value: Option<ExprValue>,
}

impl Expr {
    fn new(op: ExprOp) -> Self {
        Self {
            op,
            value: None,
            rdepth: 0,
        }
    }
}

impl Expr {
    fn init_rdepth(&mut self) {
        match &mut self.op {
            ExprOp::Hex(_) | ExprOp::Dec(_) | ExprOp::Id(_) | ExprOp::Sizeof(_) => (),
            ExprOp::Add(e0, e1)
            | ExprOp::Sub(e0, e1)
            | ExprOp::Mul(e0, e1)
            | ExprOp::LShift(e0, e1) => {
                e0.rdepth = self.rdepth;
                e0.init_rdepth();
                e1.rdepth = self.rdepth + 1;
                e1.init_rdepth();
            }
        };
    }

    pub fn map<F, U>(&self, f: &mut F) -> U
    where
        F: FnMut(&Expr, &[U]) -> U,
    {
        match &self.op {
            ExprOp::Hex(_) | ExprOp::Dec(_) | ExprOp::Id(_) | ExprOp::Sizeof(_) => f(self, &[]),
            ExprOp::Add(e0, e1)
            | ExprOp::Sub(e0, e1)
            | ExprOp::Mul(e0, e1)
            | ExprOp::LShift(e0, e1) => {
                let u0 = e0.map(f);
                let u1 = e1.map(f);
                f(self, &[u0, u1])
            }
        }
    }

    pub fn transform_in_place<F, U>(&mut self, f: &mut F) -> U
    where
        F: FnMut(&mut Expr, &[U]) -> U,
    {
        match &mut self.op {
            ExprOp::Hex(_) | ExprOp::Dec(_) | ExprOp::Id(_) | ExprOp::Sizeof(_) => f(self, &[]),
            ExprOp::Add(e0, e1)
            | ExprOp::Sub(e0, e1)
            | ExprOp::Mul(e0, e1)
            | ExprOp::LShift(e0, e1) => {
                let u0 = e0.transform_in_place(f);
                let u1 = e1.transform_in_place(f);
                f(self, &[u0, u1])
            }
        }
    }

    fn transform_strings_in_place<R: StringTransformer>(&mut self, repl: &R) {
        self.transform_in_place(&mut |e, _| match &mut e.op {
            ExprOp::Id(id) => {
                repl.transform_in_place(&mut id.name);
            }
            ExprOp::Sizeof(id) => {
                repl.transform_in_place(&mut id.name);
            }
            _ => (),
        });
    }

    pub(super) fn transform_strings<R: StringTransformer>(&self, repl: &R) -> Self {
        let mut e = self.clone();
        e.transform_strings_in_place(repl);
        e
    }

    pub(super) fn resolve_ids<I, T, U>(
        &mut self,
        resolve_expr_id: &mut I,
        resolve_sizeof_type: &mut T,
    ) -> Result<(), U>
    where
        U: Copy,
        I: FnMut(&str) -> Result<ExprResolvedId, U>,
        T: FnMut(&str) -> Result<ExprResolvedType, U>,
    {
        self.transform_in_place(&mut |e: &mut Expr, r: &[Result<(), U>]| match &mut e.op {
            ExprOp::Id(id) => match resolve_expr_id(&id.name) {
                Ok(resolved) => {
                    id.resolved = Some(resolved);
                    Ok(())
                }
                Err(err) => Err(err),
            },
            ExprOp::Sizeof(id) => match resolve_sizeof_type(&id.name) {
                Ok(resolved) => {
                    id.resolved = Some(resolved);
                    Ok(())
                }
                Err(err) => Err(err),
            },
            ExprOp::Hex(_) | ExprOp::Dec(_) => Ok(()),
            ExprOp::Add(_, _) | ExprOp::Sub(_, _) | ExprOp::Mul(_, _) | ExprOp::LShift(_, _) => {
                if r[0].is_err() {
                    r[0]
                } else {
                    r[1]
                }
            }
        })
    }
}

#[derive(Debug)]
enum ExprToken<'a> {
    Hex(&'a str),
    Dec(&'a str),
    Id(&'a str),
    Sizeof,
    LeftParen,
    RightParen,
    Plus,
    Minus,
    Mul,
    LShift,
}

struct ExprTokenIterator<'a> {
    expr: &'a str,
}

impl<'a> ExprTokenIterator<'a> {
    fn new(expr: &'a str) -> Self {
        Self { expr }
    }
}

impl<'a> Iterator for ExprTokenIterator<'a> {
    type Item = Result<ExprToken<'a>, ()>;

    fn next(&mut self) -> Option<Self::Item> {
        self.expr = self.expr.trim_start();
        if self.expr.is_empty() {
            return None;
        }

        let token = match self.expr.chars().next().unwrap() {
            '(' => {
                self.expr = &self.expr['('.len_utf8()..];
                ExprToken::LeftParen
            }
            ')' => {
                self.expr = &self.expr[')'.len_utf8()..];
                ExprToken::RightParen
            }
            '+' => {
                self.expr = &self.expr['+'.len_utf8()..];
                ExprToken::Plus
            }
            '-' => {
                self.expr = &self.expr['-'.len_utf8()..];
                ExprToken::Minus
            }
            '*' => {
                self.expr = &self.expr['*'.len_utf8()..];
                ExprToken::Mul
            }
            '<' => match self.expr.chars().nth(1) {
                Some(c) if c == '<' => {
                    self.expr = &self.expr[2 * '<'.len_utf8()..];
                    ExprToken::LShift
                }
                _ => return Some(Err(())),
            },
            '0' => {
                let (prefix_end, is_hex) = match self.expr.chars().nth(1) {
                    Some(c) if c == 'x' || c == 'X' => (c.len_utf8(), true),
                    _ => (0, false),
                };
                let prefix_end = '0'.len_utf8() + prefix_end;
                let end = match self.expr[prefix_end..].find(|c: char| {
                    if is_hex {
                        !c.is_ascii_hexdigit()
                    } else {
                        !c.is_ascii_digit()
                    }
                }) {
                    None => self.expr.len(),
                    Some(end) => prefix_end + end,
                };
                if is_hex && prefix_end == end {
                    return Some(Err(()));
                }
                let (literal, remainder) = self.expr.split_at(end);
                self.expr = remainder;
                if is_hex {
                    ExprToken::Hex(literal)
                } else {
                    ExprToken::Dec(literal)
                }
            }
            c if c.is_ascii_digit() => {
                let end = match self.expr.find(|c: char| !c.is_ascii_digit()) {
                    None => self.expr.len(),
                    Some(end) => end,
                };
                let (literal, remainder) = self.expr.split_at(end);
                self.expr = remainder;
                ExprToken::Dec(literal)
            }
            c if c.is_ascii_alphabetic() || c == '$' || c == '_' || c == '!' || c == '.' => {
                let end = match self.expr[c.len_utf8()..].find(|c: char| {
                    !c.is_ascii_alphabetic()
                        && !c.is_ascii_alphanumeric()
                        && c != '_'
                        && c != '!'
                        && c != '.'
                }) {
                    None => self.expr.len(),
                    Some(end) => c.len_utf8() + end,
                };
                let (id, remainder) = self.expr.split_at(end);
                self.expr = remainder;
                if id == "sizeof" {
                    ExprToken::Sizeof
                } else {
                    ExprToken::Id(id)
                }
            }
            _ => return Some(Err(())),
        };

        Some(Ok(token))
    }
}

#[derive(Debug)]
enum ExprParserState {
    HavePrimaryExpr,
    HaveMulExpr,
    HaveAddExpr,
    HaveShiftExpr,
    InNeg,
    InSizeof,
    InSizeofParens,
    InSizeofType,
    InParens,
    InMul,
    InAdd,
    InSub,
    InLShift,
}

// Expression parser for simple expressions as found at various places in the
// TCG TPM2 Part 2 "Structures" tables.
//
// Language productions:
//  shift_expr = add_expr |
//               shift_expr << add_expr
//
//  add_expr = mul_expr |
//             add_expr + mul_expr
//             add_expr - mul_expr
//
//  mul_expr = primary_expr |
//             mul_expr * primary
//
//  primary: <hex> | <decimal> | <id> | sizeof(<id>) | (shift_expr)
//
pub struct ExprParser {
    state_stack: Vec<ExprParserState>,
    expr_stack: Vec<Expr>,
}

impl ExprParser {
    pub fn parse(expr: &str) -> Result<Expr, ()> {
        let mut p = Self {
            state_stack: Vec::new(),
            expr_stack: Vec::new(),
        };
        let tokens = ExprTokenIterator::new(expr);
        for lookahead in tokens {
            let lookahead = match lookahead {
                Ok(token) => token,
                Err(_) => return Err(()),
            };
            p.process_tok(lookahead)?;
        }

        p.eof()
    }

    fn reduce_to_mul_expr(&mut self) {
        match self.state_stack.pop() {
            Some(ExprParserState::HavePrimaryExpr) => (),
            _ => unreachable!(),
        };
        match self.state_stack.last() {
            None
            | Some(ExprParserState::InParens)
            | Some(ExprParserState::InAdd)
            | Some(ExprParserState::InSub)
            | Some(ExprParserState::InLShift) => {
                self.state_stack.push(ExprParserState::HaveMulExpr);
            }
            Some(ExprParserState::InMul) => {
                self.state_stack.pop();
                self.state_stack.push(ExprParserState::HaveMulExpr);
                let right_op = self.expr_stack.pop().unwrap();
                let left_op = self.expr_stack.pop().unwrap();
                self.expr_stack.push(Expr::new(ExprOp::Mul(
                    Box::new(left_op),
                    Box::new(right_op),
                )));
            }
            _ => unreachable!(),
        };
    }

    fn reduce_to_add_expr(&mut self) {
        self.reduce_to_mul_expr();
        match self.state_stack.pop() {
            Some(ExprParserState::HaveMulExpr) => (),
            _ => unreachable!(),
        };
        match self.state_stack.last() {
            None | Some(ExprParserState::InParens) | Some(ExprParserState::InLShift) => {
                self.state_stack.push(ExprParserState::HaveAddExpr);
            }
            Some(ExprParserState::InAdd) => {
                self.state_stack.pop();
                self.state_stack.push(ExprParserState::HaveAddExpr);
                let right_op = self.expr_stack.pop().unwrap();
                let left_op = self.expr_stack.pop().unwrap();
                self.expr_stack.push(Expr::new(ExprOp::Add(
                    Box::new(left_op),
                    Box::new(right_op),
                )));
            }
            Some(ExprParserState::InSub) => {
                self.state_stack.pop();
                self.state_stack.push(ExprParserState::HaveAddExpr);
                let right_op = self.expr_stack.pop().unwrap();
                let left_op = self.expr_stack.pop().unwrap();
                self.expr_stack.push(Expr::new(ExprOp::Sub(
                    Box::new(left_op),
                    Box::new(right_op),
                )));
            }
            _ => unreachable!(),
        };
    }

    fn reduce_to_shift_expr(&mut self) {
        self.reduce_to_add_expr();
        match self.state_stack.pop() {
            Some(ExprParserState::HaveAddExpr) => (),
            _ => unreachable!(),
        };
        match self.state_stack.last() {
            None | Some(ExprParserState::InParens) => {
                self.state_stack.push(ExprParserState::HaveShiftExpr);
            }
            Some(ExprParserState::InLShift) => {
                self.state_stack.pop();
                self.state_stack.push(ExprParserState::HaveShiftExpr);
                let right_op = self.expr_stack.pop().unwrap();
                let left_op = self.expr_stack.pop().unwrap();
                self.expr_stack.push(Expr::new(ExprOp::LShift(
                    Box::new(left_op),
                    Box::new(right_op),
                )));
            }
            _ => unreachable!(),
        };
    }

    fn process_tok(&mut self, lookahead: ExprToken) -> Result<(), ()> {
        match lookahead {
            ExprToken::Hex(literal) => {
                match self.state_stack.last() {
                    None
                    | Some(ExprParserState::InParens)
                    | Some(ExprParserState::InMul)
                    | Some(ExprParserState::InAdd)
                    | Some(ExprParserState::InSub)
                    | Some(ExprParserState::InLShift) => {
                        self.state_stack.push(ExprParserState::HavePrimaryExpr);
                        let value = ExprConstValue::new_from_hex(literal)?;
                        let mut e = Expr::new(ExprOp::Hex(literal.to_owned()));
                        e.value = Some(ExprValue::CompiletimeConstant(value));
                        self.expr_stack.push(e);
                    }
                    _ => return Err(()),
                };
            }
            ExprToken::Dec(literal) => {
                let is_neg = if let Some(ExprParserState::InNeg) = self.state_stack.last() {
                    self.state_stack.pop();
                    true
                } else {
                    false
                };
                match self.state_stack.last() {
                    None
                    | Some(ExprParserState::InParens)
                    | Some(ExprParserState::InMul)
                    | Some(ExprParserState::InAdd)
                    | Some(ExprParserState::InSub)
                    | Some(ExprParserState::InLShift) => {
                        self.state_stack.push(ExprParserState::HavePrimaryExpr);
                        let mut literal = literal.to_owned();
                        if is_neg {
                            literal.insert(0, '-');
                        }
                        let value = ExprConstValue::new_from_dec(&literal)?;
                        let mut e = Expr::new(ExprOp::Dec(literal));
                        e.value = Some(ExprValue::CompiletimeConstant(value));
                        self.expr_stack.push(e);
                    }
                    _ => return Err(()),
                };
            }
            ExprToken::Id(id) => {
                match self.state_stack.last() {
                    None
                    | Some(ExprParserState::InParens)
                    | Some(ExprParserState::InMul)
                    | Some(ExprParserState::InAdd)
                    | Some(ExprParserState::InSub)
                    | Some(ExprParserState::InLShift) => {
                        self.state_stack.push(ExprParserState::HavePrimaryExpr);
                        self.expr_stack
                            .push(Expr::new(ExprOp::Id(ExprId::new(id.to_owned()))));
                    }
                    Some(ExprParserState::InSizeofParens) => {
                        self.state_stack.pop();
                        self.state_stack.push(ExprParserState::InSizeofType);
                        self.expr_stack
                            .push(Expr::new(ExprOp::Sizeof(ExprSizeof::new(id.to_owned()))));
                    }
                    _ => return Err(()),
                };
            }
            ExprToken::Sizeof => {
                match self.state_stack.last() {
                    None
                    | Some(ExprParserState::InParens)
                    | Some(ExprParserState::InMul)
                    | Some(ExprParserState::InAdd)
                    | Some(ExprParserState::InSub)
                    | Some(ExprParserState::InLShift) => {
                        self.state_stack.push(ExprParserState::InSizeof);
                    }
                    _ => return Err(()),
                };
            }
            ExprToken::LeftParen => {
                match self.state_stack.last() {
                    None
                    | Some(ExprParserState::InParens)
                    | Some(ExprParserState::InMul)
                    | Some(ExprParserState::InAdd)
                    | Some(ExprParserState::InSub)
                    | Some(ExprParserState::InLShift) => {
                        self.state_stack.push(ExprParserState::InParens);
                    }
                    Some(ExprParserState::InSizeof) => {
                        self.state_stack.pop();
                        self.state_stack.push(ExprParserState::InSizeofParens);
                    }
                    _ => return Err(()),
                };
            }
            ExprToken::RightParen => {
                match self.state_stack.last() {
                    Some(ExprParserState::HavePrimaryExpr) => {
                        self.reduce_to_shift_expr();
                        match self.state_stack.pop() {
                            Some(ExprParserState::HaveShiftExpr) => (),
                            _ => unreachable!(),
                        };

                        match self.state_stack.last() {
                            Some(ExprParserState::InParens) => {
                                self.state_stack.pop();
                                self.state_stack.push(ExprParserState::HavePrimaryExpr);
                                // Leave expression stack as-is.
                            }
                            _ => return Err(()),
                        };
                    }
                    Some(ExprParserState::InSizeofType) => {
                        self.state_stack.pop();
                        self.state_stack.push(ExprParserState::HavePrimaryExpr);
                    }
                    _ => return Err(()),
                };
            }
            ExprToken::Plus => {
                match self.state_stack.last() {
                    Some(ExprParserState::HavePrimaryExpr) => {
                        self.reduce_to_add_expr();
                        self.state_stack.pop();
                        self.state_stack.push(ExprParserState::InAdd);
                    }
                    _ => return Err(()),
                };
            }
            ExprToken::Minus => {
                match self.state_stack.last() {
                    Some(ExprParserState::HavePrimaryExpr) => {
                        self.reduce_to_add_expr();
                        self.state_stack.pop();
                        self.state_stack.push(ExprParserState::InSub);
                    }
                    None
                    | Some(ExprParserState::InParens)
                    | Some(ExprParserState::InMul)
                    | Some(ExprParserState::InAdd)
                    | Some(ExprParserState::InSub)
                    | Some(ExprParserState::InLShift) => {
                        self.state_stack.push(ExprParserState::InNeg);
                    }
                    _ => return Err(()),
                };
            }
            ExprToken::Mul => {
                match self.state_stack.last() {
                    Some(ExprParserState::HavePrimaryExpr) => {
                        self.reduce_to_mul_expr();
                        self.state_stack.pop();
                        self.state_stack.push(ExprParserState::InMul);
                    }
                    _ => return Err(()),
                };
            }
            ExprToken::LShift => {
                match self.state_stack.last() {
                    Some(ExprParserState::HavePrimaryExpr) => {
                        self.reduce_to_shift_expr();
                        self.state_stack.pop();
                        self.state_stack.push(ExprParserState::InLShift);
                    }
                    _ => return Err(()),
                };
            }
        }

        Ok(())
    }

    fn eof(&mut self) -> Result<Expr, ()> {
        match self.state_stack.last() {
            Some(ExprParserState::HavePrimaryExpr) => {
                self.reduce_to_shift_expr();
                self.state_stack.pop();
                if self.state_stack.is_empty() {
                    let mut e = self.expr_stack.pop().unwrap();
                    e.init_rdepth();
                    Ok(e)
                } else {
                    Err(())
                }
            }
            _ => Err(()),
        }
    }
}
