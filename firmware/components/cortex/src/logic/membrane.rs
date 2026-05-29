use core::ffi::c_char;
use core::mem::MaybeUninit;

use crate::platform;
use crate::platform::amino_acids;
use crate::platform::amino_acids::AminoAcidId;
use crate::platform::ribosome_store;
use crate::platform::ribosome_table;
use crate::platform::ribosome_table::{
    RibosomeEntryConfigRaw, RibosomeTableEntryRaw, RibosomeTableRaw,
};
use crate::platform::rna_membrane;
use crate::platform::rna_membrane::{RnaTemplateId, RnaTemplateRaw, RnaTemplateTableRaw};
use crate::platform::Result;

#[repr(C)]
pub struct MembraneState {
    pub ribosome_table: RibosomeTableRaw,
    pub rna_templates: RnaTemplateTableRaw,
}

pub struct Membrane {
    state: MembraneState,
    initialized: bool,
}

impl Membrane {
    pub fn new() -> Self {
        let mut state = MembraneState {
            ribosome_table: uninit_ribosome_table(),
            rna_templates: uninit_rna_table(),
        };

        let _ = ribosome_table::init(&mut state.ribosome_table);
        let _ = rna_membrane::table_init(&mut state.rna_templates);

        Self {
            state,
            initialized: false,
        }
    }

    pub fn init(&mut self) -> Result {
        if let Err(err) = ribosome_store::load_or_init(&mut self.state.ribosome_table) {
            self.initialized = false;
            return Err(err);
        }

        if let Err(err) = rna_membrane::load_or_init(&mut self.state.rna_templates) {
            self.initialized = false;
            return Err(err);
        }

        self.initialized = true;
        Ok(())
    }

    pub fn save(&self) -> Result {
        if !self.initialized {
            return Err(platform::ESP_ERR_INVALID_STATE);
        }

        ribosome_store::save(&self.state.ribosome_table)?;
        rna_membrane::save(&self.state.rna_templates)
    }

    pub fn initialized(&self) -> bool {
        self.initialized
    }

    pub fn allows(
        &self,
        device: &RibosomeTableEntryRaw,
        amino_id: AminoAcidId,
        payload: Option<&i32>,
    ) -> bool {
        if !self.initialized {
            return false;
        }
        if !ribosome_table::template_id_valid(device.template_id) {
            return false;
        }
        if amino_acids::validate_payload(amino_id, payload).is_err() {
            return false;
        }

        match self.find_template(device.template_id) {
            Some(template_rule) => rna_membrane::allows(template_rule, amino_id),
            None => false,
        }
    }

    pub fn get_device(
        &self,
        mqtt_client_id: *const c_char,
        out_device: &mut RibosomeTableEntryRaw,
    ) -> Result {
        if !self.initialized {
            return Err(platform::ESP_ERR_INVALID_STATE);
        }

        ribosome_table::get_entry(&self.state.ribosome_table, mqtt_client_id, out_device)
    }

    pub fn add_device(&mut self, config: &RibosomeEntryConfigRaw) -> Result {
        if !self.initialized {
            return Err(platform::ESP_ERR_INVALID_STATE);
        }
        if self.find_template(config.template_id).is_none() {
            return Err(platform::ESP_ERR_NOT_FOUND);
        }

        ribosome_table::add_from_config(&mut self.state.ribosome_table, config)
    }

    pub fn remove_device(&mut self, mqtt_client_id: *const c_char) -> Result {
        if !self.initialized {
            return Err(platform::ESP_ERR_INVALID_STATE);
        }

        ribosome_table::remove_entry(&mut self.state.ribosome_table, mqtt_client_id)
    }

    pub fn assign_template(
        &mut self,
        mqtt_client_id: *const c_char,
        template_id: RnaTemplateId,
    ) -> Result {
        if !self.initialized {
            return Err(platform::ESP_ERR_INVALID_STATE);
        }
        if self.find_template(template_id).is_none() {
            return Err(platform::ESP_ERR_NOT_FOUND);
        }

        match find_device_slot(&mut self.state.ribosome_table, mqtt_client_id) {
            Some(slot) => {
                slot.template_id = template_id;
                Ok(())
            }
            None if mqtt_client_id_valid(mqtt_client_id) => Err(platform::ESP_ERR_NOT_FOUND),
            None => Err(platform::ESP_ERR_INVALID_ARG),
        }
    }

    pub fn find_template(&self, template_id: RnaTemplateId) -> Option<&RnaTemplateRaw> {
        if !self.initialized {
            return None;
        }

        let template = rna_membrane::table_find(&self.state.rna_templates, template_id)?;
        unsafe { template.as_ref() }
    }

    pub fn template_in_use(&self, template_id: RnaTemplateId) -> bool {
        if !self.initialized || !rna_membrane::id_valid(template_id) {
            return false;
        }

        self.state
            .ribosome_table
            .entries
            .iter()
            .take(self.state.ribosome_table.count)
            .any(|entry| entry.template_id == template_id)
    }

    pub fn add_template(&mut self, template_rule: &RnaTemplateRaw) -> Result {
        if !self.initialized {
            return Err(platform::ESP_ERR_INVALID_STATE);
        }

        rna_membrane::table_add(&mut self.state.rna_templates, template_rule)
    }

    pub fn replace_template(&mut self, template_rule: &RnaTemplateRaw) -> Result {
        if !self.initialized {
            return Err(platform::ESP_ERR_INVALID_STATE);
        }
        if rna_membrane::validate(template_rule).is_err() {
            return Err(platform::ESP_ERR_INVALID_ARG);
        }

        match find_template_slot(&mut self.state.rna_templates, template_rule.id) {
            Some(slot) => {
                copy_template_sanitized(slot, template_rule);
                Ok(())
            }
            None => Err(platform::ESP_ERR_NOT_FOUND),
        }
    }

    pub fn remove_template(&mut self, template_id: RnaTemplateId) -> Result {
        if !self.initialized {
            return Err(platform::ESP_ERR_INVALID_STATE);
        }
        if !rna_membrane::id_valid(template_id) {
            return Err(platform::ESP_ERR_INVALID_ARG);
        }
        if self.template_in_use(template_id) {
            return Err(platform::ESP_ERR_INVALID_STATE);
        }

        for i in 0..self.state.rna_templates.count {
            if self.state.rna_templates.templates[i].id != template_id {
                continue;
            }

            for j in i..(self.state.rna_templates.count - 1) {
                let next = self.state.rna_templates.templates[j + 1];
                copy_template_sanitized(&mut self.state.rna_templates.templates[j], &next);
            }

            self.state.rna_templates.count -= 1;
            rna_membrane::clear(
                &mut self.state.rna_templates.templates[self.state.rna_templates.count],
            );
            return Ok(());
        }

        Err(platform::ESP_ERR_NOT_FOUND)
    }

    pub fn state(&self) -> &MembraneState {
        &self.state
    }
}

impl Default for Membrane {
    fn default() -> Self {
        Self::new()
    }
}

fn find_device_slot(
    table: &mut RibosomeTableRaw,
    mqtt_client_id: *const c_char,
) -> Option<&mut RibosomeTableEntryRaw> {
    if !mqtt_client_id_valid(mqtt_client_id) {
        return None;
    }

    table
        .entries
        .iter_mut()
        .take(table.count)
        .find(|entry| mqtt_client_id_equal(entry.mqtt_client_id.as_ptr(), mqtt_client_id))
}

fn find_template_slot(
    table: &mut RnaTemplateTableRaw,
    template_id: RnaTemplateId,
) -> Option<&mut RnaTemplateRaw> {
    if !rna_membrane::id_valid(template_id) {
        return None;
    }

    table
        .templates
        .iter_mut()
        .take(table.count)
        .find(|template| template.id == template_id)
}

fn copy_template_sanitized(dst: &mut RnaTemplateRaw, src: &RnaTemplateRaw) {
    rna_membrane::clear(dst);
    dst.id = src.id;
    dst.amino_count = src.amino_count;
    dst.flags = src.flags;
    copy_c_char_buffer(&mut dst.name, &src.name);
    dst.aminos = src.aminos;
}

fn copy_c_char_buffer(dst: &mut [c_char], src: &[c_char]) {
    if dst.is_empty() {
        return;
    }

    let limit = dst.len().saturating_sub(1).min(src.len());
    for i in 0..limit {
        dst[i] = src[i];
        if src[i] == 0 {
            return;
        }
    }

    dst[limit] = 0;
}

fn mqtt_client_id_valid(mqtt_client_id: *const c_char) -> bool {
    if mqtt_client_id.is_null() {
        return false;
    }

    unsafe {
        if *mqtt_client_id == 0 {
            return false;
        }

        for i in 0..ribosome_table::RIBOSOME_MQTT_CLIENT_ID_LEN {
            if *mqtt_client_id.add(i) == 0 {
                return true;
            }
        }
    }

    false
}

fn mqtt_client_id_equal(a: *const c_char, b: *const c_char) -> bool {
    if a.is_null() || b.is_null() {
        return false;
    }

    unsafe {
        for i in 0..ribosome_table::RIBOSOME_MQTT_CLIENT_ID_LEN {
            if *a.add(i) != *b.add(i) {
                return false;
            }
            if *a.add(i) == 0 {
                return true;
            }
        }
    }

    true
}

fn uninit_ribosome_table() -> RibosomeTableRaw {
    let table = MaybeUninit::<RibosomeTableRaw>::zeroed();
    unsafe { table.assume_init() }
}

fn uninit_rna_table() -> RnaTemplateTableRaw {
    let table = MaybeUninit::<RnaTemplateTableRaw>::zeroed();
    unsafe { table.assume_init() }
}
