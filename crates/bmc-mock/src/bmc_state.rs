/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use rand::Rng;
use rand::distr::StandardUniform;

use crate::bug::InjectedBugs;
use crate::json::json_patch;
use crate::redfish;
use crate::redfish::chassis::ChassisState;
use crate::redfish::computer_system::SystemState;
use crate::redfish::manager::ManagerState;
use crate::redfish::update_service::UpdateServiceState;

/// Dell Specific -- iDRAC job implementation
/// TODO (spyda): move most of this logic to libredfish
const DELL_JOB_TYPE: &str = "DellConfiguration";

#[derive(Debug, Clone)]
pub struct Job {
    pub job_id: String,
    pub job_state: JobState,
    pub job_type: String,
    pub start_time: chrono::DateTime<chrono::Utc>,
    pub end_time: Option<chrono::DateTime<chrono::Utc>>,
}

impl Job {
    pub fn is_dell_job(&self) -> bool {
        matches!(self.job_type.as_str(), DELL_JOB_TYPE)
    }

    pub fn percent_complete(&self) -> i32 {
        match &self.job_state {
            JobState::Completed => 100,
            _ => 0,
        }
    }
}

#[derive(Clone)]
pub struct BmcState {
    pub bmc_vendor: redfish::oem::BmcVendor,
    pub jobs: Arc<Mutex<HashMap<String, Job>>>,
    pub manager: Arc<ManagerState>,
    pub system_state: Arc<SystemState>,
    pub chassis_state: Arc<ChassisState>,
    pub update_service_state: Arc<UpdateServiceState>,
    pub dell_attrs: Arc<Mutex<serde_json::Value>>,
    pub injected_bugs: Arc<InjectedBugs>,
}

#[derive(Debug, Clone)]
pub enum JobState {
    Scheduled,
    Completed,
}

impl BmcState {
    pub fn get_job(&self, job_id: &String) -> Option<Job> {
        self.jobs.lock().unwrap().get(job_id).cloned()
    }

    pub fn add_job(&mut self) -> Result<String, Box<dyn std::error::Error>> {
        let mut jobs = self.jobs.lock().unwrap();

        let job_id = rand::rng()
            .sample_iter::<u64, _>(StandardUniform)
            .map(|r| format!("JID_{r}"))
            .find(|id| !jobs.contains_key(id))
            .unwrap();

        let job = Job {
            job_id: job_id.clone(),
            job_state: JobState::Scheduled,
            job_type: DELL_JOB_TYPE.to_string(),
            start_time: chrono::offset::Utc::now(),
            end_time: None,
        };

        jobs.insert(job_id.clone(), job);
        Ok(job_id)
    }

    pub fn complete_all_bios_jobs(&mut self) {
        let mut jobs = self.jobs.lock().unwrap();

        let bios_jobs: Vec<Job> = jobs
            .values()
            .filter(|job| job.is_dell_job())
            .cloned()
            .collect();
        for mut job in bios_jobs {
            job.job_state = JobState::Completed;
            job.end_time = Some(chrono::offset::Utc::now());
            jobs.insert(job.job_id.clone(), job);
        }
    }

    pub fn update_dell_attrs(&mut self, v: serde_json::Value) {
        let mut dell_attrs = self.dell_attrs.lock().unwrap();
        json_patch(&mut dell_attrs, v);
    }

    pub fn get_dell_attrs(&self, mut base: serde_json::Value) -> serde_json::Value {
        let dell_attrs = self.dell_attrs.lock().unwrap();
        json_patch(&mut base, dell_attrs.clone());
        base
    }
}
