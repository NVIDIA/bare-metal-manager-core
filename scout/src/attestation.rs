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

use std::str::FromStr;

use ::rpc::machine_discovery::TpmDescription;
use tss_esapi::abstraction::{ak, ek};
use tss_esapi::attributes::session::SessionAttributesBuilder;
use tss_esapi::constants::{CapabilityType, PropertyTag, SessionType};
use tss_esapi::handles::{AuthHandle, KeyHandle, SessionHandle};
use tss_esapi::interface_types::algorithm::{
    AsymmetricAlgorithm, HashingAlgorithm, SignatureSchemeAlgorithm,
};
use tss_esapi::interface_types::session_handles::PolicySession;
use tss_esapi::structures::PcrSlot;
use tss_esapi::structures::SymmetricDefinition;
use tss_esapi::structures::{
    Attest, CapabilityData::TpmProperties, Data, Digest, EncryptedSecret, HashScheme,
    PcrSelectionListBuilder, Signature,
};
use tss_esapi::structures::{IdObject, SignatureScheme};
use tss_esapi::traits::Marshall;
use tss_esapi::Context;
use tss_esapi::TctiNameConf;

use std::process::Command;
use std::vec::Vec;

use crate::{cfg::Options, client::create_forge_client, CarbideClientError};
use ::rpc::forge as rpc;

pub async fn run(config: &Options, machine_id: &str) -> Result<(), CarbideClientError> {
    // create gRPC client
    let mut client = create_forge_client(config).await?;

    // create context
    let mut ctx = create_context_from_config(config)
        .map_err(|e| CarbideClientError::TpmError(format!("Could not create context: {0}", e)))?;

    let result = create_bind_request(&mut ctx, machine_id).map_err(|e| {
        CarbideClientError::TpmError(format!("Could not create Bind Request: {0}", e))
    })?;

    let ek_handle = result.1;
    let ak_handle = result.2;

    let bind_response = client.bind_attest_key(result.0).await?;

    tracing::info!("Sent bind attest request and received reply");
    tracing::info!(
        "cred_blob - {} bytes long, secret - {} bytes long",
        bind_response.get_ref().cred_blob.len(),
        bind_response.get_ref().encrypted_secret.len()
    );

    // retrieve credential (kind of AuthToken) from the bind_response
    let cred =
        activate_credential(&bind_response, &mut ctx, &ek_handle, &ak_handle).map_err(|e| {
            CarbideClientError::TpmError(format!("Could not activate credential: {0}", e))
        })?;

    // obtain signed attestation (a hash of pcr values) and actual pcr values
    let (attest, signature, pcr_values) = get_pcr_quote(&mut ctx, &ak_handle)
        .map_err(|e| CarbideClientError::TpmError(format!("Could not get PCR Quote: {0}", e)))?;

    tracing::info!("Obtained PCR quote");

    let tpm_eventlog = get_tpm_eventlog();

    // create Quote Request message
    let quote_request = create_quote_request(
        attest,
        signature,
        pcr_values,
        &cred,
        machine_id,
        &tpm_eventlog,
    )
    .map_err(|e| CarbideClientError::TpmError(format!("Could not create quote request: {0}", e)))?;
    // send to server
    let _quote_response = client.verify_quote(quote_request).await?;

    Ok(())
}

fn create_context_from_path(path: &str) -> Result<Context, Box<dyn std::error::Error>> {
    let tcti = TctiNameConf::from_str(path)?;
    // create context
    let ctx = Context::new(tcti)?;
    Ok(ctx)
}

fn create_context_from_config(config: &Options) -> Result<Context, Box<dyn std::error::Error>> {
    // create tcti - an interface to talk to TPM
    create_context_from_path(&config.tpm_path)
}

fn create_bind_request(
    ctx: &mut Context,
    machine_id: &str,
) -> Result<(tonic::Request<rpc::BindRequest>, KeyHandle, KeyHandle), Box<dyn std::error::Error>> {
    // obtain EK
    let ek_handle = ek::create_ek_object(ctx, AsymmetricAlgorithm::Rsa, None)?;
    tracing::debug!("Obtained EK handle");
    // create AK
    let ak = ak::create_ak(
        ctx,
        ek_handle,
        HashingAlgorithm::Sha256,
        SignatureSchemeAlgorithm::RsaPss,
        None,
        None,
    )?;
    // load ak - get handle, we'll need it for getting obj name and signing later
    let ak_handle = ak::load_ak(
        ctx,
        ek_handle,
        None,
        ak.out_private.clone(),
        ak.out_public.clone(),
    )?;

    tracing::debug!("Created and loaded AK");

    // read public - get ak name (cryptographic)
    let (_, ak_key_name, _) = ctx.read_public(ak_handle)?;
    let (ek_public, _, _) = ctx.read_public(ek_handle)?;

    // create rpc message now
    let bind_request = tonic::Request::new(rpc::BindRequest {
        machine_id: Some(machine_id.to_string().into()),
        ak_pub: ak.out_public.marshall()?,
        ak_name: Vec::from(ak_key_name.value()),
        ek_pub: ek_public.marshall()?,
    });

    Ok((bind_request, ek_handle, ak_handle))
}

fn activate_credential(
    response: &tonic::Response<rpc::BindResponse>,
    ctx: &mut Context,
    ek_handle: &KeyHandle,
    ak_handle: &KeyHandle,
) -> Result<Digest, Box<dyn std::error::Error>> {
    // use activate credential to obtain the credential (nonce)
    let cred_blob = IdObject::try_from(response.get_ref().cred_blob.clone())?;
    let encr_secret = EncryptedSecret::try_from(response.get_ref().encrypted_secret.clone())?;

    // in order to call activate_credential, we need a policy auth session. this session acts as a vehicle for enforcing that
    // PolicySecret is applied, i.e. that we have access to the endorsement key
    let ek_auth_session_option = ctx.start_auth_session(
        None,
        None,
        None,
        SessionType::Policy,
        SymmetricDefinition::AES_256_CFB,
        HashingAlgorithm::Sha256,
    )?;

    let ek_auth_session = match ek_auth_session_option {
        Some(auth_session) => auth_session,
        None => {
            return Err(Box::new(CarbideClientError::TpmError(
                "Could not start auth session 1".to_string(),
            )));
        }
    };

    // hmac auth session is needed for authorising access to the ak key. please note that this is not an extra policy key, but
    // rather a separate session on specific key
    let ak_auth_session_option = ctx.start_auth_session(
        None,
        None,
        None,
        SessionType::Hmac,
        SymmetricDefinition::AES_256_CFB,
        HashingAlgorithm::Sha256,
    )?;

    let ak_auth_session = match ak_auth_session_option {
        Some(auth_session) => auth_session,
        None => {
            return Err(Box::new(CarbideClientError::TpmError(
                "Could not start auth session 2".to_string(),
            )));
        }
    };

    let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new().build();

    ctx.tr_sess_set_attributes(ek_auth_session, session_attributes, session_attributes_mask)?;
    ctx.tr_sess_set_attributes(ak_auth_session, session_attributes, session_attributes_mask)?;

    let _ = ctx.execute_with_session(ak_auth_session_option, |ctx| {
        ctx.policy_secret(
            PolicySession::try_from(ek_auth_session)?,
            AuthHandle::Endorsement,
            Default::default(),
            Default::default(),
            Default::default(),
            None,
        )
    })?;

    ctx.set_sessions((ak_auth_session_option, ek_auth_session_option, None));

    let digest = ctx.activate_credential(*ak_handle, *ek_handle, cred_blob, encr_secret)?;

    tracing::debug!(
        "Activated credential with session key value of {:?} ",
        digest.value()
    );

    ctx.flush_context(SessionHandle::from(ak_auth_session).into())?;
    ctx.flush_context(SessionHandle::from(ek_auth_session).into())?;
    ctx.clear_sessions();

    Ok(digest)
}

fn get_pcr_quote(
    ctx: &mut Context,
    ak_handle: &KeyHandle,
) -> Result<(Attest, Signature, Vec<Digest>), Box<dyn std::error::Error>> {
    let ak_auth_session_option = ctx.start_auth_session(
        None,
        None,
        None,
        SessionType::Hmac,
        SymmetricDefinition::AES_256_CFB,
        HashingAlgorithm::Sha256,
    )?;

    let ak_auth_session = match ak_auth_session_option {
        Some(auth_session) => auth_session,
        None => {
            return Err(Box::new(CarbideClientError::TpmError(
                "Could not start auth session".to_string(),
            )));
        }
    };

    let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new().build();

    ctx.tr_sess_set_attributes(ak_auth_session, session_attributes, session_attributes_mask)?;

    let selection_list = PcrSelectionListBuilder::new()
        .with_selection(
            HashingAlgorithm::Sha256,
            &[
                PcrSlot::Slot0,
                PcrSlot::Slot1,
                PcrSlot::Slot2,
                PcrSlot::Slot3,
                PcrSlot::Slot4,
                PcrSlot::Slot5,
                PcrSlot::Slot6,
                PcrSlot::Slot7,
                PcrSlot::Slot8,
                PcrSlot::Slot9,
                PcrSlot::Slot10,
                PcrSlot::Slot11,
            ],
        )
        .build()?;

    // this apparently means "no qualifying data" - whatever that is ...
    let qualifying_data = vec![0xff; 16];

    ctx.set_sessions((ak_auth_session_option, None, None));
    // get the quote and the signature
    let (attest, signature) = ctx.quote(
        *ak_handle,
        Data::try_from(qualifying_data)?,
        SignatureScheme::RsaPss {
            hash_scheme: HashScheme::new(HashingAlgorithm::Sha256),
        },
        selection_list.clone(),
    )?;

    tracing::debug!("Obtained attestation {:?}", attest);
    tracing::debug!("Obtained signature {:?}", signature);

    //verify_signature(ctx, &attest, &signature, &ak_handle);

    // clean up sessions as soon as we are finished with them
    ctx.clear_sessions();
    ctx.flush_context(SessionHandle::from(ak_auth_session).into())?;

    // get the actual pcr values
    let mut selection_list_mut = selection_list;
    let mut digest_vec = Vec::<Digest>::new();

    loop {
        let (_, read_list, pcr_list) = ctx.pcr_read(selection_list_mut.clone())?;
        digest_vec.extend_from_slice(pcr_list.value());

        if read_list.is_empty() {
            break;
        }

        selection_list_mut.subtract(&read_list)?;
    }

    tracing::debug!("Obtained pcr digests {:?}", digest_vec);

    Ok((attest, signature, digest_vec))
}

fn create_quote_request(
    attestation: Attest,
    signature: Signature,
    pcr_values: Vec<Digest>,
    credential: &Digest,
    machine_id: &str,
    tpm_eventlog: &Option<Vec<u8>>,
) -> Result<tonic::Request<rpc::VerifyQuoteRequest>, Box<dyn std::error::Error>> {
    let request = tonic::Request::new(rpc::VerifyQuoteRequest {
        attestation: attestation.marshall()?,
        signature: signature.marshall()?,
        credential: Vec::from(credential.value()),
        pcr_values: pcr_values
            .iter()
            .map(|digest| Vec::from(digest.value()))
            .collect(),
        machine_id: Some(machine_id.to_string().into()),
        event_log: tpm_eventlog.clone(),
    });

    Ok(request)
}

fn get_tpm_eventlog() -> Option<Vec<u8>> {
    let output_res = Command::new("sh")
        .arg("-c")
        .arg("tpm2_eventlog /sys/kernel/security/tpm0/binary_bios_measurements")
        .output();

    let output = match output_res {
        Ok(output) => output,
        Err(e) => {
            tracing::error!("Could not retrieve TPM Event Log {0}", e.to_string());
            return None;
        }
    };

    if !output.status.success() {
        tracing::error!(
            "Error retrieving TPM Event Log: {0}",
            String::from_utf8(output.stderr).unwrap_or("<could not parse stderr log>".to_string())
        );
        None
    } else {
        Some(output.stdout)
    }
}

pub fn get_tpm_description(path: &str) -> Option<TpmDescription> {
    let mut ctx = match create_context_from_path(path) {
        Ok(ctx) => ctx,
        Err(e) => {
            tracing::error!("GetTpmDescription: Could not create TPM context: {e}");
            return None;
        }
    };

    let (capabilities, _more) = match ctx.get_capability(CapabilityType::TpmProperties, 0, 80) {
        Ok(tuple) => tuple,
        Err(e) => {
            tracing::error!("GetTpmDescription: could not get TPM capability data: {e}");
            return None;
        }
    };

    let tpm_properties = match capabilities.clone() {
        TpmProperties(property_list) => property_list,
        _ => {
            tracing::error!("Failed to call get TpmProperties");
            return None;
        }
    };

    let mut firmware_version_1 = 0u32;
    let mut firmware_version_2 = 0u32;
    let mut spec_version = String::default();
    let mut vendor_1 = String::default();
    let mut vendor_2 = String::default();

    for tagged_property in tpm_properties {
        match tagged_property.property() {
            // this is spec version
            PropertyTag::FamilyIndicator => {
                spec_version = String::from_utf8(tagged_property.value().to_be_bytes().to_vec())
                    .unwrap_or("Could not convert spec_version".to_string())
            }
            PropertyTag::VendorString1 => {
                vendor_1 = String::from_utf8(tagged_property.value().to_be_bytes().to_vec())
                    .unwrap_or("Could not convert vendor_1".to_string())
            }
            PropertyTag::VendorString2 => {
                vendor_2 = String::from_utf8(tagged_property.value().to_be_bytes().to_vec())
                    .unwrap_or("Could not convert vendor_2".to_string())
            }
            PropertyTag::FirmwareVersion1 => firmware_version_1 = tagged_property.value(),
            PropertyTag::FirmwareVersion2 => firmware_version_2 = tagged_property.value(),
            _ => (),
        }
    }

    tracing::debug!("family_indicator is {0}", spec_version);

    let vendor = vendor_1.clone() + &vendor_2;
    tracing::debug!("vendor is {0}", vendor);

    let firmware_version = format!("0x{:x}.0x{:x}", firmware_version_1, firmware_version_2);

    tracing::debug!("firmware version is {0}", firmware_version);

    if firmware_version_1 == 0
        && firmware_version_2 == 0
        && vendor_1 == String::default()
        && vendor_2 == String::default()
        && spec_version == String::default()
    {
        tracing::error!("GetTpmDescription: could not extract tpm description");
        return None;
    }

    Some(TpmDescription {
        tpm_spec: spec_version,
        vendor,
        firmware_version,
    })
}
