// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

use std::io::{self, Write};

use crate::tcg_tpm2::structures;
use crate::tcg_tpm2::structures::deps::ConfigDepsDisjunction;
use structures::algs::AlgoFlagsMasksOr;
use structures::predefined::{
    PredefinedConstantRef, PredefinedConstants, PredefinedTypeRef, PredefinedTypes,
};
use structures::table_common::{ClosureDeps, ClosureDepsFlags};
use structures::tables::StructuresPartTablesIndex;

use super::{Tpm2InterfaceRustCodeGenerator, code_writer};

impl<'a> Tpm2InterfaceRustCodeGenerator<'a> {
    pub(super) fn gen_limits_def<W: io::Write>(
        &self,
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
    ) -> Result<(), io::Error> {
        let mut predefined_constants: Vec<(PredefinedConstantRef, &ClosureDeps)> = self
            .tables
            .structures
            .predefined_constants_deps
            .iter()
            .map(|(p, deps)| (PredefinedConstants::lookup(p).unwrap(), deps))
            .collect();
        predefined_constants.sort_by_key(|p| p.0.name);

        writeln!(out, "#[derive(Clone, Debug)]")?;
        writeln!(out, "pub struct TpmLimits {{")?;
        let mut iout = out.make_indent();
        let mut need_impl = false;
        for (p, deps) in predefined_constants.iter() {
            if !p.is_primary() {
                need_impl = true;
                continue;
            }

            let deps = deps.collect_config_deps(ClosureDepsFlags::ANY_DEFINITION);
            if !deps.is_unconditional_true() {
                writeln!(&mut iout, "#[cfg({})]", Self::format_deps(&deps))?;
            }
            let t = PredefinedTypes::lookup(p.value_type).unwrap();
            writeln!(
                &mut iout,
                "pub {}: {},",
                p.name.to_ascii_lowercase(),
                Self::predefined_type_to_rust(t)
            )?;
        }
        writeln!(out, "}}")?;

        if !need_impl {
            return Ok(());
        }

        writeln!(out, "impl TpmLimits {{")?;
        let mut iout = out.make_indent();
        let mut first = true;
        for (p, deps) in predefined_constants.iter() {
            if p.is_primary() {
                continue;
            }

            if !first {
                writeln!(&mut iout)?;
            }
            first = false;

            let deps = deps.collect_config_deps(ClosureDepsFlags::ANY_DEFINITION);
            if !deps.is_unconditional_true() {
                writeln!(&mut iout, "#[cfg({})]", Self::format_deps(&deps))?;
            }
            let t = PredefinedTypes::lookup(p.value_type).unwrap();
            writeln!(
                &mut iout,
                "fn {}(&self) -> Result<{}, ()> {{",
                p.name.to_ascii_lowercase(),
                Self::predefined_type_to_rust(t)
            )?;

            let mut iiout = iout.make_indent();
            match p.name {
                "LABEL_MAX_BUFFER" => self.gen_predefined_label_max_buffer(&mut iiout, &t)?,
                "MAX_ACT_DATA" => self.gen_predefined_max_act_data(&mut iiout, &t)?,
                "MAX_AC_CAPABILITIES" => self.gen_predefined_max_ac_capabilities(&mut iiout, &t)?,
                "MAX_CAP_ALGS" => self.gen_predefined_max_cap_algs(&mut iiout, &t)?,
                "MAX_CAP_CC" => self.gen_predefined_max_cap_cc(&mut iiout, &t)?,
                "MAX_CAP_DATA" => self.gen_predefined_max_cap_data(&mut iiout, &t)?,
                "MAX_CAP_HANDLES" => self.gen_predefined_max_cap_handles(&mut iiout, &t)?,
                "MAX_DIGEST_SIZE" => self.gen_predefined_max_digest_size(&mut iiout, &t, &deps)?,
                "MAX_ECC_CURVES" => self.gen_predefined_max_ecc_curves(&mut iiout, &t)?,
                "MAX_ECC_KEY_BYTES" => {
                    self.gen_predefined_max_ecc_key_bytes(&mut iiout, &t, &deps)?
                }
                "MAX_PCR_PROPERTIES" => self.gen_predefined_max_pcr_properties(&mut iiout, &t)?,
                "MAX_PUB_KEYS" => self.gen_predefined_max_pub_keys(&mut iiout, &t)?,
                "MAX_SPDM_SESSION_INFO" => {
                    self.gen_predefined_max_spdm_session_info(&mut iiout, &t)?
                }
                "MAX_SYM_BLOCK_SIZE" => {
                    self.gen_predefined_max_sym_block_size(&mut iiout, &t, &deps)?
                }
                "MAX_SYM_DATA" => self.gen_predefined_max_sym_data(&mut iiout, &t)?,
                "MAX_SYM_KEY_BYTES" => {
                    self.gen_predefined_max_sym_key_bytes(&mut iiout, &t, &deps)?
                }
                "MAX_TAGGED_POLICIES" => self.gen_predefined_max_tagged_policies(&mut iiout, &t)?,
                "MAX_TPM_PROPERTIES" => self.gen_predefined_max_tpm_properties(&mut iiout, &t)?,
                "MAX_VENDOR_PROPERTY" => self.gen_predefined_max_vendor_property(&mut iiout, &t)?,
                "PCR_SELECT_MAX" => self.gen_predefined_pcr_select_max(&mut iiout, &t)?,
                "PCR_SELECT_MIN" => self.gen_predefined_pcr_select_min(&mut iiout, &t)?,
                _ => {
                    eprintln!("error: unknown predefined constant \"{}\"", p.name);
                    return Err(io::Error::from(io::ErrorKind::InvalidData));
                }
            };

            writeln!(&mut iout, "}}")?;
        }
        writeln!(out, "}}")?;

        Ok(())
    }

    fn gen_predefined_body_predefined_constant_ref<W: io::Write>(
        &self,
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
        predefined: &str,
    ) -> Result<(String, PredefinedTypeRef), io::Error> {
        let predefined = PredefinedConstants::lookup(predefined).unwrap();
        let t = PredefinedTypes::lookup(predefined.value_type).unwrap();
        let name = predefined.name.to_ascii_lowercase();

        if predefined.is_primary() {
            Ok(("self.".to_owned() + &name, t))
        } else {
            writeln!(out, "let {} = self.{}()?;", &name, &name)?;
            Ok((name, t))
        }
    }

    fn gen_predefined_body_sizeof_ref<W: io::Write>(
        &self,
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
        type_id: &str,
        target_type_hint: Option<PredefinedTypeRef>,
    ) -> Result<(String, PredefinedTypeRef, bool), io::Error> {
        let resolved = self
            .tables
            .structures
            .resolve_expr_sizeof_type("limits", type_id)
            .unwrap();
        let type_id = type_id.to_ascii_lowercase();
        let (sizeof_ref, t, primitive, can_fail) = self
            .format_sizeof_ref(&resolved, target_type_hint, "self")
            .map_err(|_| {
                eprintln!(
                    "error: {}: failed to generated sizeof() expression",
                    type_id
                );
                io::Error::from(io::ErrorKind::InvalidData)
            })?;

        let name = format!("sizeof_{}", type_id.to_ascii_lowercase());
        let (sizeof_ref, primitive) = if can_fail {
            writeln!(out, "let {} = {}?;", &name, sizeof_ref)?;
            (name, true)
        } else {
            (sizeof_ref, primitive)
        };

        Ok((sizeof_ref, t, primitive))
    }

    fn gen_predefined_body_cast<W: io::Write>(
        &self,
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
        target_type: PredefinedTypeRef,
        name: String,
        e: String,
        t: PredefinedTypeRef,
        primitive: bool,
    ) -> Result<(String, bool), io::Error> {
        if target_type == t {
            Ok((e, primitive))
        } else if (target_type.signed == t.signed && target_type.bits >= t.bits)
            || (target_type.signed && target_type.bits > t.bits)
        {
            Ok((
                format!("{} as {}", e, Self::predefined_type_to_rust(target_type)),
                false,
            ))
        } else {
            writeln!(
                out,
                "let {} = {}::try_from({}).or(Err(()))?;",
                &name,
                Self::predefined_type_to_rust(target_type),
                e
            )?;
            Ok((name, true))
        }
    }

    fn gen_predefined_label_max_buffer<W: io::Write>(
        &self,
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
        target_type: &PredefinedTypeRef,
    ) -> Result<(), io::Error> {
        let name = "label_max_buffer";

        let (max_digest_size, max_digest_size_t) =
            self.gen_predefined_body_predefined_constant_ref(out, "MAX_DIGEST_SIZE")?;
        let (max_ecc_key_bytes, max_ecc_key_bytes_t) =
            self.gen_predefined_body_predefined_constant_ref(out, "MAX_ECC_KEY_BYTES")?;

        let common_t = PredefinedTypes::find_common_type(max_digest_size_t, max_ecc_key_bytes_t)
            .ok_or_else(|| {
                eprintln!(
                    "error: {}: failed to find common type for limit computation",
                    name
                );
                io::Error::from(io::ErrorKind::InvalidData)
            })?;
        let (max_digest_size, max_digest_size_p) = self.gen_predefined_body_cast(
            out,
            common_t,
            "max_digest_size".to_owned(),
            max_digest_size,
            max_digest_size_t,
            true,
        )?;
        let (max_ecc_key_bytes, _max_ecc_key_bytes_p) = self.gen_predefined_body_cast(
            out,
            common_t,
            "max_ecc_key_bytes".to_owned(),
            max_ecc_key_bytes,
            max_ecc_key_bytes_t,
            true,
        )?;

        let max_digest_size = if max_digest_size_p {
            max_digest_size
        } else {
            "(".to_owned() + &max_digest_size + ")"
        };
        let label_max_buffer = format!("{}.max({}).min(32)", max_digest_size, max_ecc_key_bytes);
        let (label_max_buffer, _label_max_buffer_p) = self.gen_predefined_body_cast(
            out,
            *target_type,
            name.to_owned(),
            label_max_buffer,
            common_t,
            true,
        )?;
        writeln!(out, "Ok({})", label_max_buffer)?;
        Ok(())
    }

    fn gen_predefined_max_act_data<W: io::Write>(
        &self,
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
        target_type: &PredefinedTypeRef,
    ) -> Result<(), io::Error> {
        let name = "max_act_data";

        let (max_cap_data, max_cap_data_t) =
            self.gen_predefined_body_predefined_constant_ref(out, "MAX_CAP_DATA")?;
        let (sz_tpms_act_data, sz_tpms_act_data_t, sz_tpms_act_data_p) =
            self.gen_predefined_body_sizeof_ref(out, "TPMS_ACT_DATA", Some(max_cap_data_t))?;

        let common_t = PredefinedTypes::find_common_type(max_cap_data_t, sz_tpms_act_data_t)
            .ok_or_else(|| {
                eprintln!(
                    "error: {}: failed to find common type for limit computation",
                    name
                );
                io::Error::from(io::ErrorKind::InvalidData)
            })?;
        let (max_cap_data, max_cap_data_p) = self.gen_predefined_body_cast(
            out,
            common_t,
            "max_cap_data".to_owned(),
            max_cap_data,
            max_cap_data_t,
            true,
        )?;
        let (sz_tpms_act_data, _sz_tpms_act_data_p) = self.gen_predefined_body_cast(
            out,
            common_t,
            "sizeof_tpms_act_data".to_owned(),
            sz_tpms_act_data,
            sz_tpms_act_data_t,
            sz_tpms_act_data_p,
        )?;

        let max_cap_data = if max_cap_data_p {
            max_cap_data
        } else {
            "(".to_owned() + &max_cap_data + ")"
        };

        writeln!(
            out,
            "let {} = {}.checked_div({}).ok_or(())?;",
            name, max_cap_data, sz_tpms_act_data
        )?;
        let (result, _) = self.gen_predefined_body_cast(
            out,
            *target_type,
            name.to_owned(),
            name.to_owned(),
            common_t,
            true,
        )?;
        writeln!(out, "Ok({})", result)?;
        Ok(())
    }

    fn gen_predefined_max_ac_capabilities<W: io::Write>(
        &self,
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
        target_type: &PredefinedTypeRef,
    ) -> Result<(), io::Error> {
        let name = "max_ac_capabilities";

        let (max_cap_data, max_cap_data_t) =
            self.gen_predefined_body_predefined_constant_ref(out, "MAX_CAP_DATA")?;
        let (sz_tpms_ac_output, sz_tpms_ac_output_t, sz_tpms_ac_output_p) =
            self.gen_predefined_body_sizeof_ref(out, "TPMS_AC_OUTPUT", Some(max_cap_data_t))?;

        let common_t = PredefinedTypes::find_common_type(max_cap_data_t, sz_tpms_ac_output_t)
            .ok_or_else(|| {
                eprintln!(
                    "error: {}: failed to find common type for limit computation",
                    name
                );
                io::Error::from(io::ErrorKind::InvalidData)
            })?;
        let (max_cap_data, max_cap_data_p) = self.gen_predefined_body_cast(
            out,
            common_t,
            "max_cap_data".to_owned(),
            max_cap_data,
            max_cap_data_t,
            true,
        )?;
        let (sz_tpms_ac_output, _sz_tpms_ac_output_p) = self.gen_predefined_body_cast(
            out,
            common_t,
            "sizeof_tpms_ac_output".to_owned(),
            sz_tpms_ac_output,
            sz_tpms_ac_output_t,
            sz_tpms_ac_output_p,
        )?;

        let max_cap_data = if max_cap_data_p {
            max_cap_data
        } else {
            "(".to_owned() + &max_cap_data + ")"
        };

        writeln!(
            out,
            "let {} = {}.checked_div({}).ok_or(())?;",
            name, max_cap_data, sz_tpms_ac_output
        )?;
        let (result, _) = self.gen_predefined_body_cast(
            out,
            *target_type,
            name.to_owned(),
            name.to_owned(),
            common_t,
            true,
        )?;
        writeln!(out, "Ok({})", result)?;
        Ok(())
    }

    fn gen_predefined_max_cap_algs<W: io::Write>(
        &self,
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
        target_type: &PredefinedTypeRef,
    ) -> Result<(), io::Error> {
        let name = "max_cap_algs";

        let (max_cap_data, max_cap_data_t) =
            self.gen_predefined_body_predefined_constant_ref(out, "MAX_CAP_DATA")?;
        let (sz_tpms_alg_property, sz_tpms_alg_property_t, sz_tpms_alg_property_p) =
            self.gen_predefined_body_sizeof_ref(out, "TPMS_ALG_PROPERTY", Some(max_cap_data_t))?;

        let common_t = PredefinedTypes::find_common_type(max_cap_data_t, sz_tpms_alg_property_t)
            .ok_or_else(|| {
                eprintln!(
                    "error: {}: failed to find common type for limit computation",
                    name
                );
                io::Error::from(io::ErrorKind::InvalidData)
            })?;
        let (max_cap_data, max_cap_data_p) = self.gen_predefined_body_cast(
            out,
            common_t,
            "max_cap_data".to_owned(),
            max_cap_data,
            max_cap_data_t,
            true,
        )?;
        let (sz_tpms_alg_property, _sz_tpms_alg_property_p) = self.gen_predefined_body_cast(
            out,
            common_t,
            "sizeof_tpms_alg_property".to_owned(),
            sz_tpms_alg_property,
            sz_tpms_alg_property_t,
            sz_tpms_alg_property_p,
        )?;

        let max_cap_data = if max_cap_data_p {
            max_cap_data
        } else {
            "(".to_owned() + &max_cap_data + ")"
        };

        writeln!(
            out,
            "let {} = {}.checked_div({}).ok_or(())?;",
            name, max_cap_data, sz_tpms_alg_property
        )?;
        let (result, _) = self.gen_predefined_body_cast(
            out,
            *target_type,
            name.to_owned(),
            name.to_owned(),
            common_t,
            true,
        )?;
        writeln!(out, "Ok({})", result)?;
        Ok(())
    }

    fn gen_predefined_max_cap_cc<W: io::Write>(
        &self,
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
        target_type: &PredefinedTypeRef,
    ) -> Result<(), io::Error> {
        let name = "max_cap_cc";

        let (max_cap_data, max_cap_data_t) =
            self.gen_predefined_body_predefined_constant_ref(out, "MAX_CAP_DATA")?;
        let (sz_tpm_cc, sz_tpm_cc_t, sz_tpm_cc_p) =
            self.gen_predefined_body_sizeof_ref(out, "TPM_CC", Some(max_cap_data_t))?;

        let common_t =
            PredefinedTypes::find_common_type(max_cap_data_t, sz_tpm_cc_t).ok_or_else(|| {
                eprintln!(
                    "error: {}: failed to find common type for limit computation",
                    name
                );
                io::Error::from(io::ErrorKind::InvalidData)
            })?;
        let (max_cap_data, max_cap_data_p) = self.gen_predefined_body_cast(
            out,
            common_t,
            "max_cap_data".to_owned(),
            max_cap_data,
            max_cap_data_t,
            true,
        )?;
        let (sz_tpm_cc, _sz_tpm_cc_p) = self.gen_predefined_body_cast(
            out,
            common_t,
            "sizeof_tpm_cc".to_owned(),
            sz_tpm_cc,
            sz_tpm_cc_t,
            sz_tpm_cc_p,
        )?;

        let max_cap_data = if max_cap_data_p {
            max_cap_data
        } else {
            "(".to_owned() + &max_cap_data + ")"
        };

        writeln!(
            out,
            "let {} = {}.checked_div({}).ok_or(())?;",
            name, max_cap_data, sz_tpm_cc
        )?;
        let (result, _) = self.gen_predefined_body_cast(
            out,
            *target_type,
            name.to_owned(),
            name.to_owned(),
            common_t,
            true,
        )?;
        writeln!(out, "Ok({})", result)?;
        Ok(())
    }

    fn gen_predefined_max_cap_data<W: io::Write>(
        &self,
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
        target_type: &PredefinedTypeRef,
    ) -> Result<(), io::Error> {
        let name = "max_cap_data";

        let (max_cap_buffer, max_cap_buffer_t) =
            self.gen_predefined_body_predefined_constant_ref(out, "MAX_CAP_BUFFER")?;
        let (sz_tpm_cap, sz_tpm_cap_t, sz_tpm_cap_p) =
            self.gen_predefined_body_sizeof_ref(out, "TPM_CAP", Some(max_cap_buffer_t))?;

        let common_t = PredefinedTypes::find_common_type(max_cap_buffer_t, sz_tpm_cap_t)
            .ok_or_else(|| {
                eprintln!(
                    "error: {}: failed to find common type for limit computation",
                    name
                );
                io::Error::from(io::ErrorKind::InvalidData)
            })?;
        let (max_cap_buffer, max_cap_buffer_p) = self.gen_predefined_body_cast(
            out,
            common_t,
            "max_cap_buffer".to_owned(),
            max_cap_buffer,
            max_cap_buffer_t,
            true,
        )?;
        let (sz_tpm_cap, _sz_tpm_cap_p) = self.gen_predefined_body_cast(
            out,
            common_t,
            "sizeof_tpm_cap".to_owned(),
            sz_tpm_cap,
            sz_tpm_cap_t,
            sz_tpm_cap_p,
        )?;

        let max_cap_buffer = if max_cap_buffer_p {
            max_cap_buffer
        } else {
            "(".to_owned() + &max_cap_buffer + ")"
        };

        let max_cap_data = format!(
            "{}.checked_sub({}).ok_or(())?.checked_sub(4).ok_or(())?",
            max_cap_buffer, sz_tpm_cap
        );
        let (max_cap_data, _max_cap_data_p) = self.gen_predefined_body_cast(
            out,
            *target_type,
            name.to_owned(),
            max_cap_data,
            common_t,
            true,
        )?;
        writeln!(out, "Ok({})", max_cap_data)?;
        Ok(())
    }

    fn gen_predefined_max_cap_handles<W: io::Write>(
        &self,
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
        target_type: &PredefinedTypeRef,
    ) -> Result<(), io::Error> {
        let name = "max_cap_handles";

        let (max_cap_data, max_cap_data_t) =
            self.gen_predefined_body_predefined_constant_ref(out, "MAX_CAP_DATA")?;
        let (sz_tpm_handle, sz_tpm_handle_t, sz_tpm_handle_p) =
            self.gen_predefined_body_sizeof_ref(out, "TPM_HANDLE", Some(max_cap_data_t))?;

        let common_t = PredefinedTypes::find_common_type(max_cap_data_t, sz_tpm_handle_t)
            .ok_or_else(|| {
                eprintln!(
                    "error: {}: failed to find common type for limit computation",
                    name
                );
                io::Error::from(io::ErrorKind::InvalidData)
            })?;
        let (max_cap_data, max_cap_data_p) = self.gen_predefined_body_cast(
            out,
            common_t,
            "max_cap_data".to_owned(),
            max_cap_data,
            max_cap_data_t,
            true,
        )?;
        let (sz_tpm_handle, _sz_tpm_handle_p) = self.gen_predefined_body_cast(
            out,
            common_t,
            "sizeof_tpm_handle".to_owned(),
            sz_tpm_handle,
            sz_tpm_handle_t,
            sz_tpm_handle_p,
        )?;

        let max_cap_data = if max_cap_data_p {
            max_cap_data
        } else {
            "(".to_owned() + &max_cap_data + ")"
        };

        writeln!(
            out,
            "let {} = {}.checked_div({}).ok_or(())?;",
            name, max_cap_data, sz_tpm_handle
        )?;
        let (result, _) = self.gen_predefined_body_cast(
            out,
            *target_type,
            name.to_owned(),
            name.to_owned(),
            common_t,
            true,
        )?;
        writeln!(out, "Ok({})", result)?;
        Ok(())
    }

    fn gen_predefined_max_digest_size<W: io::Write>(
        &self,
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
        target_type: &PredefinedTypeRef,
        deps: &ConfigDepsDisjunction,
    ) -> Result<(), io::Error> {
        writeln!(
            out,
            "let mut max_digest_size: {} = 0;",
            Self::predefined_type_to_rust(*target_type)
        )?;

        let alg_registry = self
            .tables
            .structures
            .alg_registry
            .as_ref()
            .ok_or_else(|| {
                eprintln!("error: no algorithm registry, needed for MAX_DIGEST_SIZE generation");
                io::Error::from(io::ErrorKind::InvalidData)
            })?;

        for hash in alg_registry.iter(&AlgoFlagsMasksOr::try_from("H").unwrap()) {
            let hash_name = hash.name.to_ascii_uppercase();
            let hash_defines = self
                .tables
                .structures
                .lookup_hash_defines_table(&hash_name)
                .ok_or_else(|| {
                    eprintln!(
                        "error: no hash defines for {}, needed for generating MAX_DIGEST_SIZE",
                        hash_name
                    );
                    io::Error::from(io::ErrorKind::InvalidData)
                })?;

            let alg_id_name = "TPM_ALG_".to_owned() + hash_name.as_str();
            let alg_id_constant = self
                .tables
                .structures
                .lookup_constant(&alg_id_name)
                .ok_or_else(|| {
                    eprintln!(
                        "error: no definition of \"{}\", needed for MAX_DIGEST_SIZE generation",
                        alg_id_name
                    );
                    io::Error::from(io::ErrorKind::InvalidData)
                })?;
            let alg_id_constant = self.tables.structures.get_constant(alg_id_constant);
            let hash_deps = alg_id_constant.deps.factor_by_common_of(deps);

            let mut iout = if !hash_deps.is_unconditional_true() {
                writeln!(out, "#[cfg({})]", Self::format_dep_conjunction(&hash_deps))?;
                writeln!(out, "{{")?;
                out.make_indent()
            } else {
                out.make_same_indent()
            };

            writeln!(
                &mut iout,
                "max_digest_size = max_digest_size.max({});",
                hash_defines.digest_size
            )?;

            if !hash_deps.is_unconditional_true() {
                writeln!(out, "}}")?;
            }
        }

        writeln!(out)?;
        writeln!(out, "Ok(max_digest_size)")?;
        Ok(())
    }

    fn gen_predefined_max_ecc_curves<W: io::Write>(
        &self,
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
        target_type: &PredefinedTypeRef,
    ) -> Result<(), io::Error> {
        let name = "max_ecc_curves";

        let (max_cap_data, max_cap_data_t) =
            self.gen_predefined_body_predefined_constant_ref(out, "MAX_CAP_DATA")?;
        let (sz_tpm_ecc_curve, sz_tpm_ecc_curve_t, sz_tpm_ecc_curve_p) =
            self.gen_predefined_body_sizeof_ref(out, "TPM_ECC_CURVE", Some(max_cap_data_t))?;

        let common_t = PredefinedTypes::find_common_type(max_cap_data_t, sz_tpm_ecc_curve_t)
            .ok_or_else(|| {
                eprintln!(
                    "error: {}: failed to find common type for limit computation",
                    name
                );
                io::Error::from(io::ErrorKind::InvalidData)
            })?;
        let (max_cap_data, max_cap_data_p) = self.gen_predefined_body_cast(
            out,
            common_t,
            "max_cap_data".to_owned(),
            max_cap_data,
            max_cap_data_t,
            true,
        )?;
        let (sz_tpm_ecc_curve, _sz_tpm_ecc_curve_p) = self.gen_predefined_body_cast(
            out,
            common_t,
            "sizeof_tpm_ecc_curve".to_owned(),
            sz_tpm_ecc_curve,
            sz_tpm_ecc_curve_t,
            sz_tpm_ecc_curve_p,
        )?;

        let max_cap_data = if max_cap_data_p {
            max_cap_data
        } else {
            "(".to_owned() + &max_cap_data + ")"
        };

        writeln!(
            out,
            "let {} = {}.checked_div({}).ok_or(())?;",
            name, max_cap_data, sz_tpm_ecc_curve
        )?;
        let (result, _) = self.gen_predefined_body_cast(
            out,
            *target_type,
            name.to_owned(),
            name.to_owned(),
            common_t,
            true,
        )?;
        writeln!(out, "Ok({})", result)?;
        Ok(())
    }

    fn gen_predefined_max_ecc_key_bytes<W: io::Write>(
        &self,
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
        target_type: &PredefinedTypeRef,
        deps: &ConfigDepsDisjunction,
    ) -> Result<(), io::Error> {
        let ecc_curves = self.tables.structures.lookup("TPM_ECC_CURVE").ok_or_else(|| {
            eprintln!("error: no definition for TPM_ECC_CURVE, needed for generating MAX_ECC_KEY_BYTES");
            io::Error::from(io::ErrorKind::InvalidData)
        })?;
        let ecc_curves = match ecc_curves {
            StructuresPartTablesIndex::Constants(index) => {
                self.tables.structures.get_constants(index)
            }
            _ => {
                eprintln!(
                    "error: TPM_ECC_CURVE table, needed for generating MAX_ECC_KEY_BYTES, is not a Constants table"
                );
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }
        };

        writeln!(
            out,
            "let mut max_ecc_key_bits: {} = 0;",
            Self::predefined_type_to_rust(*target_type)
        )?;
        for ecc_curve in ecc_curves.entries.iter() {
            if ecc_curve.name.ends_with("_NONE") {
                continue;
            }

            let ecc_curve_defines = self
                .tables
                .structures
                .lookup_ecc_defines_table(&ecc_curve.name)
                .ok_or_else(|| {
                    eprintln!(
                        "error: no ECC defines for {}, needed for generating MAX_ECC_KEY_BYTES",
                        &ecc_curve.name
                    );
                    io::Error::from(io::ErrorKind::InvalidData)
                })?;

            let ecc_curve_deps = &ecc_curve.deps;
            let ecc_curve_deps = ecc_curve_deps.factor_by_common_of(deps);
            let mut iout = if !ecc_curve_deps.is_unconditional_true() {
                writeln!(
                    out,
                    "#[cfg({})]",
                    Self::format_dep_conjunction(&ecc_curve_deps)
                )?;
                writeln!(out, "{{")?;
                out.make_indent()
            } else {
                out.make_same_indent()
            };

            writeln!(
                &mut iout,
                "max_ecc_key_bits = max_ecc_key_bits.max({});",
                ecc_curve_defines.key_size
            )?;

            if !ecc_curve_deps.is_unconditional_true() {
                writeln!(out, "}}")?;
            }
        }

        writeln!(out)?;
        writeln!(out, "Ok(max_ecc_key_bits.checked_add(7).ok_or(())? / 8)")?;

        Ok(())
    }

    fn gen_predefined_max_pcr_properties<W: io::Write>(
        &self,
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
        target_type: &PredefinedTypeRef,
    ) -> Result<(), io::Error> {
        let name = "max_pcr_properties";

        let (max_cap_data, max_cap_data_t) =
            self.gen_predefined_body_predefined_constant_ref(out, "MAX_CAP_DATA")?;
        let (sz_tpms_tagged_pcr_select, sz_tpms_tagged_pcr_select_t, sz_tpms_tagged_pcr_select_p) =
            self.gen_predefined_body_sizeof_ref(
                out,
                "TPMS_TAGGED_PCR_SELECT",
                Some(max_cap_data_t),
            )?;

        let common_t =
            PredefinedTypes::find_common_type(max_cap_data_t, sz_tpms_tagged_pcr_select_t)
                .ok_or_else(|| {
                    eprintln!(
                        "error: {}: failed to find common type for limit computation",
                        name
                    );
                    io::Error::from(io::ErrorKind::InvalidData)
                })?;
        let (max_cap_data, max_cap_data_p) = self.gen_predefined_body_cast(
            out,
            common_t,
            "max_cap_data".to_owned(),
            max_cap_data,
            max_cap_data_t,
            true,
        )?;
        let (sz_tpms_tagged_pcr_select, _sz_tpms_tagged_pcr_select_p) = self
            .gen_predefined_body_cast(
                out,
                common_t,
                "sizeof_tpms_tagged_pcr_select".to_owned(),
                sz_tpms_tagged_pcr_select,
                sz_tpms_tagged_pcr_select_t,
                sz_tpms_tagged_pcr_select_p,
            )?;

        let max_cap_data = if max_cap_data_p {
            max_cap_data
        } else {
            "(".to_owned() + &max_cap_data + ")"
        };

        writeln!(
            out,
            "let {} = {}.checked_div({}).ok_or(())?;",
            name, max_cap_data, sz_tpms_tagged_pcr_select
        )?;
        let (result, _) = self.gen_predefined_body_cast(
            out,
            *target_type,
            name.to_owned(),
            name.to_owned(),
            common_t,
            true,
        )?;
        writeln!(out, "Ok({})", result)?;
        Ok(())
    }

    fn gen_predefined_max_pub_keys<W: io::Write>(
        &self,
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
        target_type: &PredefinedTypeRef,
    ) -> Result<(), io::Error> {
        let name = "max_pcr_properties";

        let (max_cap_data, max_cap_data_t) =
            self.gen_predefined_body_predefined_constant_ref(out, "MAX_CAP_DATA")?;
        let (sz_tpm2b_public, sz_tpm2b_public_t, sz_tpm2b_public_p) =
            self.gen_predefined_body_sizeof_ref(out, "TPM2B_PUBLIC", Some(max_cap_data_t))?;

        let common_t = PredefinedTypes::find_common_type(max_cap_data_t, sz_tpm2b_public_t)
            .ok_or_else(|| {
                eprintln!(
                    "error: {}: failed to find common type for limit computation",
                    name
                );
                io::Error::from(io::ErrorKind::InvalidData)
            })?;
        let (max_cap_data, max_cap_data_p) = self.gen_predefined_body_cast(
            out,
            common_t,
            "max_cap_data".to_owned(),
            max_cap_data,
            max_cap_data_t,
            true,
        )?;
        let (sz_tpm2b_public, _sz_tpm2b_public_p) = self.gen_predefined_body_cast(
            out,
            common_t,
            "sizeof_tpm2b_public".to_owned(),
            sz_tpm2b_public,
            sz_tpm2b_public_t,
            sz_tpm2b_public_p,
        )?;

        let max_cap_data = if max_cap_data_p {
            max_cap_data
        } else {
            "(".to_owned() + &max_cap_data + ")"
        };

        writeln!(
            out,
            "let {} = {}.checked_div({}).ok_or(())?;",
            name, max_cap_data, sz_tpm2b_public
        )?;
        let (result, _) = self.gen_predefined_body_cast(
            out,
            *target_type,
            name.to_owned(),
            name.to_owned(),
            common_t,
            true,
        )?;
        writeln!(out, "Ok({})", result)?;
        Ok(())
    }

    fn gen_predefined_max_spdm_session_info<W: io::Write>(
        &self,
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
        target_type: &PredefinedTypeRef,
    ) -> Result<(), io::Error> {
        let name = "max_pcr_properties";

        let (max_cap_data, max_cap_data_t) =
            self.gen_predefined_body_predefined_constant_ref(out, "MAX_CAP_DATA")?;
        let (sz_tpms_spdm_session_info, sz_tpms_spdm_session_info_t, sz_tpms_spdm_session_info_p) =
            self.gen_predefined_body_sizeof_ref(
                out,
                "TPMS_SPDM_SESSION_INFO",
                Some(max_cap_data_t),
            )?;

        let common_t =
            PredefinedTypes::find_common_type(max_cap_data_t, sz_tpms_spdm_session_info_t)
                .ok_or_else(|| {
                    eprintln!(
                        "error: {}: failed to find common type for limit computation",
                        name
                    );
                    io::Error::from(io::ErrorKind::InvalidData)
                })?;
        let (max_cap_data, max_cap_data_p) = self.gen_predefined_body_cast(
            out,
            common_t,
            "max_cap_data".to_owned(),
            max_cap_data,
            max_cap_data_t,
            true,
        )?;
        let (sz_tpms_spdm_session_info, _sz_tpms_spdm_session_info_p) = self
            .gen_predefined_body_cast(
                out,
                common_t,
                "sizeof_tpms_spdm_session_info".to_owned(),
                sz_tpms_spdm_session_info,
                sz_tpms_spdm_session_info_t,
                sz_tpms_spdm_session_info_p,
            )?;

        let max_cap_data = if max_cap_data_p {
            max_cap_data
        } else {
            "(".to_owned() + &max_cap_data + ")"
        };

        writeln!(
            out,
            "let {} = {}.checked_div({}).ok_or(())?;",
            name, max_cap_data, sz_tpms_spdm_session_info
        )?;
        let (result, _) = self.gen_predefined_body_cast(
            out,
            *target_type,
            name.to_owned(),
            name.to_owned(),
            common_t,
            true,
        )?;
        writeln!(out, "Ok({})", result)?;
        Ok(())
    }

    fn gen_predefined_max_sym_block_size<W: io::Write>(
        &self,
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
        target_type: &PredefinedTypeRef,
        deps: &ConfigDepsDisjunction,
    ) -> Result<(), io::Error> {
        writeln!(
            out,
            "let mut max_sym_block_size_bits: {} = 0;",
            Self::predefined_type_to_rust(*target_type)
        )?;

        let alg_registry = self
            .tables
            .structures
            .alg_registry
            .as_ref()
            .ok_or_else(|| {
                eprintln!("error: no algorithm registry, needed for MAX_SYM_BLOCK_SIZE generation");
                io::Error::from(io::ErrorKind::InvalidData)
            })?;

        for symcipher in alg_registry.iter(&AlgoFlagsMasksOr::try_from("S").unwrap()) {
            let symcipher_name = symcipher.name.to_ascii_uppercase();
            let symcipher_defines = self.tables.structures.lookup_symcipher_defines_table(&symcipher_name)
                .ok_or_else(|| {
                    eprintln!(
                        "error: no symmetric cipher defines for {}, needed for generating MAX_SYM_BLOCK_SIZE",
                        symcipher_name
                    );
                    io::Error::from(io::ErrorKind::InvalidData)
                })?;

            let symcipher_max_block_size_bits = symcipher_defines
                .block_sizes_bits
                .iter()
                .copied()
                .max()
                .unwrap_or(0);
            if symcipher_max_block_size_bits == 0 {
                continue;
            }

            let alg_id_name = "TPM_ALG_".to_owned() + symcipher_name.as_str();
            let alg_id_constant = self
                .tables
                .structures
                .lookup_constant(&alg_id_name)
                .ok_or_else(|| {
                    eprintln!(
                        "error: no definition of \"{}\", needed for MAX_SYM_BLOCK_SIZE generation",
                        alg_id_name
                    );
                    io::Error::from(io::ErrorKind::InvalidData)
                })?;
            let alg_id_constant = self.tables.structures.get_constant(alg_id_constant);
            let symcipher_deps = alg_id_constant.deps.factor_by_common_of(deps);

            let mut iout = if !symcipher_deps.is_unconditional_true() {
                writeln!(
                    out,
                    "#[cfg({})]",
                    Self::format_dep_conjunction(&symcipher_deps)
                )?;
                writeln!(out, "{{")?;
                out.make_indent()
            } else {
                out.make_same_indent()
            };

            writeln!(
                &mut iout,
                "max_sym_block_size_bits = max_sym_block_size_bits.max({});",
                symcipher_max_block_size_bits
            )?;

            if !symcipher_deps.is_unconditional_true() {
                writeln!(out, "}}")?;
            }
        }

        writeln!(out)?;
        writeln!(
            out,
            "Ok(max_sym_block_size_bits.checked_add(7).ok_or(())? / 8)"
        )?;
        Ok(())
    }

    fn gen_predefined_max_sym_data<W: io::Write>(
        &self,
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
        target_type: &PredefinedTypeRef,
    ) -> Result<(), io::Error> {
        writeln!(
            out,
            "Ok(128{})",
            Self::predefined_type_to_rust(*target_type)
        )?;
        Ok(())
    }

    fn gen_predefined_max_sym_key_bytes<W: io::Write>(
        &self,
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
        target_type: &PredefinedTypeRef,
        deps: &ConfigDepsDisjunction,
    ) -> Result<(), io::Error> {
        writeln!(
            out,
            "let mut max_sym_key_bits: {} = 0;",
            Self::predefined_type_to_rust(*target_type)
        )?;

        let alg_registry = self
            .tables
            .structures
            .alg_registry
            .as_ref()
            .ok_or_else(|| {
                eprintln!("error: no algorithm registry, needed for MAX_SYM_KEY_BYTES generation");
                io::Error::from(io::ErrorKind::InvalidData)
            })?;

        for symcipher in alg_registry.iter(&AlgoFlagsMasksOr::try_from("S").unwrap()) {
            let symcipher_name = symcipher.name.to_ascii_uppercase();
            let symcipher_defines = self.tables.structures.lookup_symcipher_defines_table(&symcipher_name)
                .ok_or_else(|| {
                    eprintln!(
                        "error: no symmetric cipher defines for {}, needed for generating MAX_SYM_KEY_BYTES",
                        symcipher_name
                    );
                    io::Error::from(io::ErrorKind::InvalidData)
                })?;

            let symcipher_max_key_bits = symcipher_defines
                .key_sizes_bits
                .iter()
                .copied()
                .max()
                .unwrap_or(0);
            if symcipher_max_key_bits == 0 {
                continue;
            }

            let alg_id_name = "TPM_ALG_".to_owned() + symcipher_name.as_str();
            let alg_id_constant = self
                .tables
                .structures
                .lookup_constant(&alg_id_name)
                .ok_or_else(|| {
                    eprintln!(
                        "error: no definition of \"{}\", needed for MAX_SYM_KEY_BYTES generation",
                        alg_id_name
                    );
                    io::Error::from(io::ErrorKind::InvalidData)
                })?;
            let alg_id_constant = self.tables.structures.get_constant(alg_id_constant);
            let symcipher_deps = alg_id_constant.deps.factor_by_common_of(deps);

            let mut iout = if !symcipher_deps.is_unconditional_true() {
                writeln!(
                    out,
                    "#[cfg({})]",
                    Self::format_dep_conjunction(&symcipher_deps)
                )?;
                writeln!(out, "{{")?;
                out.make_indent()
            } else {
                out.make_same_indent()
            };

            writeln!(
                &mut iout,
                "max_sym_key_bits = max_sym_key_bits.max({});",
                symcipher_max_key_bits
            )?;

            if !symcipher_deps.is_unconditional_true() {
                writeln!(out, "}}")?;
            }
        }

        writeln!(out)?;
        writeln!(
            out,
            "let max_sym_key_bytes = max_sym_key_bits.checked_add(7).ok_or(())? / 8;"
        )?;

        writeln!(out)?;
        let (max_digest_size, max_digest_size_t) =
            self.gen_predefined_body_predefined_constant_ref(out, "MAX_DIGEST_SIZE")?;
        let (max_digest_size, _max_digest_size_p) = self.gen_predefined_body_cast(
            out,
            *target_type,
            "max_digest_size".to_owned(),
            max_digest_size,
            max_digest_size_t,
            true,
        )?;

        writeln!(out)?;
        writeln!(out, "Ok(max_sym_key_bytes.max({}))", max_digest_size)?;
        Ok(())
    }

    fn gen_predefined_max_tagged_policies<W: io::Write>(
        &self,
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
        target_type: &PredefinedTypeRef,
    ) -> Result<(), io::Error> {
        let name = "max_tagged_policies";

        let (max_cap_data, max_cap_data_t) =
            self.gen_predefined_body_predefined_constant_ref(out, "MAX_CAP_DATA")?;
        let (sz_tpms_tagged_policy, sz_tpms_tagged_policy_t, sz_tpms_tagged_policy_p) =
            self.gen_predefined_body_sizeof_ref(out, "TPMS_TAGGED_POLICY", Some(max_cap_data_t))?;

        let common_t = PredefinedTypes::find_common_type(max_cap_data_t, sz_tpms_tagged_policy_t)
            .ok_or_else(|| {
            eprintln!(
                "error: {}: failed to find common type for limit computation",
                name
            );
            io::Error::from(io::ErrorKind::InvalidData)
        })?;
        let (max_cap_data, max_cap_data_p) = self.gen_predefined_body_cast(
            out,
            common_t,
            "max_cap_data".to_owned(),
            max_cap_data,
            max_cap_data_t,
            true,
        )?;
        let (sz_tpms_tagged_policy, _sz_tpms_tagged_policy_p) = self.gen_predefined_body_cast(
            out,
            common_t,
            "sizeof_tpms_tagged_policy".to_owned(),
            sz_tpms_tagged_policy,
            sz_tpms_tagged_policy_t,
            sz_tpms_tagged_policy_p,
        )?;

        let max_cap_data = if max_cap_data_p {
            max_cap_data
        } else {
            "(".to_owned() + &max_cap_data + ")"
        };

        writeln!(
            out,
            "let {} = {}.checked_div({}).ok_or(())?;",
            name, max_cap_data, sz_tpms_tagged_policy
        )?;
        let (result, _) = self.gen_predefined_body_cast(
            out,
            *target_type,
            name.to_owned(),
            name.to_owned(),
            common_t,
            true,
        )?;
        writeln!(out, "Ok({})", result)?;
        Ok(())
    }

    fn gen_predefined_max_tpm_properties<W: io::Write>(
        &self,
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
        target_type: &PredefinedTypeRef,
    ) -> Result<(), io::Error> {
        let name = "max_tpm_properties";

        let (max_cap_data, max_cap_data_t) =
            self.gen_predefined_body_predefined_constant_ref(out, "MAX_CAP_DATA")?;
        let (sz_tpms_tagged_property, sz_tpms_tagged_property_t, sz_tpms_tagged_property_p) =
            self.gen_predefined_body_sizeof_ref(out, "TPMS_TAGGED_PROPERTY", Some(max_cap_data_t))?;

        let common_t = PredefinedTypes::find_common_type(max_cap_data_t, sz_tpms_tagged_property_t)
            .ok_or_else(|| {
                eprintln!(
                    "error: {}: failed to find common type for limit computation",
                    name
                );
                io::Error::from(io::ErrorKind::InvalidData)
            })?;
        let (max_cap_data, max_cap_data_p) = self.gen_predefined_body_cast(
            out,
            common_t,
            "max_cap_data".to_owned(),
            max_cap_data,
            max_cap_data_t,
            true,
        )?;
        let (sz_tpms_tagged_property, _sz_tpms_tagged_property_p) = self.gen_predefined_body_cast(
            out,
            common_t,
            "sizeof_tpms_tagged_property".to_owned(),
            sz_tpms_tagged_property,
            sz_tpms_tagged_property_t,
            sz_tpms_tagged_property_p,
        )?;

        let max_cap_data = if max_cap_data_p {
            max_cap_data
        } else {
            "(".to_owned() + &max_cap_data + ")"
        };

        writeln!(
            out,
            "let {} = {}.checked_div({}).ok_or(())?;",
            name, max_cap_data, sz_tpms_tagged_property
        )?;
        let (result, _) = self.gen_predefined_body_cast(
            out,
            *target_type,
            name.to_owned(),
            name.to_owned(),
            common_t,
            true,
        )?;
        writeln!(out, "Ok({})", result)?;
        Ok(())
    }

    fn gen_predefined_max_vendor_property<W: io::Write>(
        &self,
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
        target_type: &PredefinedTypeRef,
    ) -> Result<(), io::Error> {
        let name = "max_pcr_properties";

        let (max_cap_data, max_cap_data_t) =
            self.gen_predefined_body_predefined_constant_ref(out, "MAX_CAP_DATA")?;
        let (sz_tpm2b_vendor_property, sz_tpm2b_vendor_property_t, sz_tpm2b_vendor_property_p) =
            self.gen_predefined_body_sizeof_ref(
                out,
                "TPM2B_VENDOR_PROPERTY",
                Some(max_cap_data_t),
            )?;

        let common_t =
            PredefinedTypes::find_common_type(max_cap_data_t, sz_tpm2b_vendor_property_t)
                .ok_or_else(|| {
                    eprintln!(
                        "error: {}: failed to find common type for limit computation",
                        name
                    );
                    io::Error::from(io::ErrorKind::InvalidData)
                })?;
        let (max_cap_data, max_cap_data_p) = self.gen_predefined_body_cast(
            out,
            common_t,
            "max_cap_data".to_owned(),
            max_cap_data,
            max_cap_data_t,
            true,
        )?;
        let (sz_tpm2b_vendor_property, _sz_tpm2b_vendor_property_p) = self
            .gen_predefined_body_cast(
                out,
                common_t,
                "sizeof_tpm2b_vendor_property".to_owned(),
                sz_tpm2b_vendor_property,
                sz_tpm2b_vendor_property_t,
                sz_tpm2b_vendor_property_p,
            )?;

        let max_cap_data = if max_cap_data_p {
            max_cap_data
        } else {
            "(".to_owned() + &max_cap_data + ")"
        };

        writeln!(
            out,
            "let {} = {}.checked_div({}).ok_or(())?;",
            name, max_cap_data, sz_tpm2b_vendor_property
        )?;
        let (result, _) = self.gen_predefined_body_cast(
            out,
            *target_type,
            name.to_owned(),
            name.to_owned(),
            common_t,
            true,
        )?;
        writeln!(out, "Ok({})", result)?;
        Ok(())
    }

    fn gen_predefined_pcr_select_max<W: io::Write>(
        &self,
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
        target_type: &PredefinedTypeRef,
    ) -> Result<(), io::Error> {
        let name = "pcr_select_max";

        let (implementation_pcr, implementation_pcr_t) =
            self.gen_predefined_body_predefined_constant_ref(out, "IMPLEMENTATION_PCR")?;
        let pcr_select_max = format!("{}.checked_add(7).ok_or(())? / 8", implementation_pcr);
        let (result, _) = self.gen_predefined_body_cast(
            out,
            *target_type,
            name.to_owned(),
            pcr_select_max,
            implementation_pcr_t,
            false,
        )?;
        writeln!(out, "Ok({})", result)?;
        Ok(())
    }

    fn gen_predefined_pcr_select_min<W: io::Write>(
        &self,
        out: &mut code_writer::IndentedCodeWriter<'_, W>,
        target_type: &PredefinedTypeRef,
    ) -> Result<(), io::Error> {
        let name = "pcr_select_min";

        let (platform_pcr, platform_pcr_t) =
            self.gen_predefined_body_predefined_constant_ref(out, "PLATFORM_PCR")?;
        let pcr_select_min = format!("{}.checked_add(7).ok_or(())? / 8", platform_pcr);
        let (result, _) = self.gen_predefined_body_cast(
            out,
            *target_type,
            name.to_owned(),
            pcr_select_min,
            platform_pcr_t,
            false,
        )?;
        writeln!(out, "Ok({})", result)?;
        Ok(())
    }
}
