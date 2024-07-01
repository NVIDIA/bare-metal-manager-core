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

pub mod common;

#[cfg(feature = "tss-esapi")]
mod tests {

    use super::*;

    use std::str::FromStr;

    use carbide::model::machine::machine_id::MachineId;
    use common::api_fixtures::create_test_env;
    use rpc::forge::forge_server::Forge;
    use rpc::forge::BindRequest;
    use rpc::forge::VerifyQuoteRequest;
    use tonic::Code;

    const AK_PUB_SERIALIZED: [u8; 280] = [
        0, 1, 0, 11, 0, 5, 0, 114, 0, 0, 0, 16, 0, 22, 0, 11, 8, 0, 0, 0, 0, 0, 1, 0, 197, 213,
        201, 224, 218, 94, 188, 183, 101, 132, 200, 245, 5, 232, 37, 49, 46, 89, 171, 230, 112, 64,
        108, 96, 58, 72, 174, 85, 166, 92, 183, 204, 143, 55, 133, 49, 77, 28, 39, 124, 70, 37, 8,
        1, 193, 98, 160, 78, 38, 93, 164, 193, 58, 190, 52, 86, 9, 240, 67, 124, 143, 234, 210,
        191, 94, 201, 101, 1, 173, 112, 22, 215, 193, 216, 13, 113, 66, 164, 145, 200, 243, 44, 54,
        79, 127, 213, 172, 9, 171, 144, 79, 54, 204, 235, 64, 110, 214, 14, 18, 95, 236, 222, 224,
        63, 64, 150, 70, 88, 197, 94, 148, 35, 53, 118, 59, 239, 177, 84, 76, 142, 243, 255, 208,
        29, 117, 172, 108, 156, 103, 76, 54, 247, 179, 248, 187, 19, 223, 218, 24, 75, 106, 82,
        213, 217, 181, 5, 9, 3, 83, 97, 235, 254, 66, 141, 160, 237, 76, 81, 101, 173, 220, 108,
        243, 220, 95, 152, 6, 184, 58, 156, 46, 5, 150, 211, 190, 65, 208, 50, 210, 135, 189, 234,
        232, 209, 87, 142, 91, 54, 237, 156, 31, 38, 132, 221, 228, 194, 197, 55, 25, 37, 214, 125,
        186, 37, 46, 220, 98, 114, 69, 24, 83, 115, 178, 191, 226, 69, 35, 78, 29, 138, 255, 148,
        61, 123, 87, 150, 134, 49, 203, 154, 98, 15, 6, 181, 8, 116, 186, 23, 89, 154, 163, 138,
        191, 75, 137, 244, 46, 17, 161, 235, 34, 84, 236, 232, 87, 25,
    ];

    const AK_NAME_SERIALIZED: [u8; 34] = [
        0, 11, 156, 103, 195, 162, 106, 182, 77, 69, 39, 156, 55, 160, 196, 165, 213, 65, 105, 238,
        251, 75, 243, 144, 166, 24, 132, 177, 159, 77, 184, 23, 17, 253,
    ];

    #[ctor::ctor]
    fn setup() {
        common::test_logging::init();
    }

    // apparently GitLab pipelines don't allow writing to disk or the default location for TempDir is not writable
    #[ignore]
    #[sqlx::test]
    async fn test_bind_attest_key_success_returns_bind_response(pool: sqlx::PgPool) {
        let env = create_test_env(pool).await;
        let host_id =
            MachineId::from_str("fm100hseddco33hvlofuqvg543p6p9aj60g76q5cq491g9m9tgtf2dk0530")
                .unwrap();

        let ek_pub = [
            0, 1, 0, 11, 0, 3, 0, 178, 0, 32, 131, 113, 151, 103, 68, 132, 179, 248, 26, 144, 204,
            141, 70, 165, 215, 36, 253, 82, 215, 110, 6, 82, 11, 100, 242, 161, 218, 27, 51, 20,
            105, 170, 0, 6, 0, 128, 0, 67, 0, 16, 8, 0, 0, 0, 0, 0, 1, 0, 161, 6, 212, 135, 171,
            109, 37, 41, 140, 162, 195, 208, 28, 179, 230, 10, 240, 68, 50, 63, 156, 87, 145, 116,
            187, 226, 155, 98, 39, 45, 151, 92, 237, 12, 163, 23, 222, 219, 192, 54, 202, 86, 88,
            126, 33, 221, 129, 226, 234, 88, 157, 181, 78, 232, 181, 248, 75, 150, 214, 90, 154,
            231, 177, 168, 97, 214, 69, 237, 147, 77, 89, 191, 188, 209, 36, 87, 92, 145, 236, 231,
            206, 100, 177, 159, 40, 65, 177, 177, 91, 116, 173, 114, 128, 82, 70, 2, 225, 214, 11,
            241, 253, 134, 12, 160, 205, 34, 148, 77, 77, 114, 165, 237, 25, 36, 65, 183, 193, 35,
            138, 64, 183, 59, 240, 142, 126, 67, 81, 15, 120, 9, 13, 94, 220, 12, 99, 225, 130, 91,
            81, 223, 183, 122, 0, 224, 243, 84, 239, 188, 147, 44, 149, 78, 90, 246, 180, 255, 71,
            44, 4, 20, 114, 46, 234, 213, 115, 123, 21, 3, 29, 161, 52, 203, 172, 186, 8, 84, 2,
            127, 252, 152, 219, 56, 144, 177, 9, 125, 234, 93, 78, 118, 126, 101, 38, 59, 174, 103,
            249, 86, 7, 2, 97, 246, 117, 79, 1, 222, 12, 64, 167, 15, 41, 67, 140, 66, 124, 100,
            236, 245, 2, 227, 26, 68, 132, 104, 156, 96, 53, 225, 169, 180, 84, 182, 67, 143, 162,
            63, 156, 13, 6, 118, 37, 35, 105, 163, 200, 56, 233, 254, 7, 165, 40, 33, 189, 226,
            206, 145,
        ];

        let bind_request = tonic::Request::new(BindRequest {
            machine_id: Some(host_id.to_string().into()),
            ak_pub: AK_PUB_SERIALIZED.to_vec(),
            ak_name: AK_NAME_SERIALIZED.to_vec(),
            ek_pub: ek_pub.to_vec(),
        });

        let res = env.api.bind_attest_key(bind_request).await;

        match res {
            Ok(bind_response) => {
                assert_eq!(bind_response.get_ref().cred_blob.len(), 68);
                assert_eq!(bind_response.get_ref().encrypted_secret.len(), 256);
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }

    #[sqlx::test]
    async fn test_bind_attest_key_make_cred_fails_returns_error(pool: sqlx::PgPool) {
        let env = create_test_env(pool).await;
        let host_id =
            MachineId::from_str("fm100hseddco33hvlofuqvg543p6p9aj60g76q5cq491g9m9tgtf2dk0530")
                .unwrap();

        // ek_pub is corrupted on purpose
        let ek_pub_corrupted = [
            0, 44, 204, 141, 70, 165, 215, 36, 253, 82, 215, 110, 6, 82, 11, 100, 242, 161, 218,
            27, 51, 20, 105, 170, 0, 6, 0, 128, 0, 67, 0, 16, 8, 0, 0, 0, 0, 0, 1, 0, 161, 6, 212,
            135, 171, 109, 37, 41, 140, 162, 195, 208, 28, 179, 230, 10, 240, 68, 50, 63, 156, 87,
            145, 116, 187, 226, 155, 98, 39, 45, 151, 92, 237, 12, 163, 23, 222, 219, 192, 54, 202,
            86, 88, 126, 33, 221, 129, 226, 234, 88, 157, 181, 78, 232, 181, 248, 75, 150, 214, 90,
            154, 231, 177, 168, 97, 214, 69, 237, 147, 77, 89, 191, 188, 209, 36, 87, 92, 145, 236,
            231, 206, 100, 177, 159, 40, 65, 177, 177, 91, 116, 173, 114, 128, 82, 70, 2, 225, 214,
            11, 241, 253, 134, 12, 160, 205, 34, 148, 77, 77, 114, 165, 237, 25, 36, 65, 183, 193,
            35, 138, 64, 183, 59, 240, 142, 126, 67, 81, 15, 120, 9, 13, 94, 220, 12, 99, 225, 130,
            91, 81, 223, 183, 122, 0, 224, 243, 84, 239, 188, 147, 44, 149, 78, 90, 246, 180, 255,
            71, 44, 4, 20, 114, 46, 234, 213, 115, 123, 21, 3, 29, 161, 52, 203, 172, 186, 8, 84,
            2, 127, 252, 152, 219, 56, 144, 177, 9, 125, 234, 93, 78, 118, 126, 101, 38, 59, 174,
            103, 249, 86, 7, 2, 97, 246, 117, 79, 1, 222, 12, 64, 167, 15, 41, 67, 140, 66, 124,
            100, 236, 245, 2, 227, 26, 68, 132, 104, 156, 96, 53, 225, 169, 180, 84, 182, 67, 143,
            162, 63, 156, 13, 6, 118, 37, 35, 105, 163, 200, 56, 233, 254, 7, 165, 40, 33, 189,
            226, 206, 145,
        ];

        let bind_request = tonic::Request::new(BindRequest {
            machine_id: Some(host_id.to_string().into()),
            ak_pub: AK_PUB_SERIALIZED.to_vec(),
            ak_name: AK_NAME_SERIALIZED.to_vec(),
            ek_pub: ek_pub_corrupted.to_vec(),
        });

        let res = env.api.bind_attest_key(bind_request).await;

        match res {
            Ok(_) => panic!("Unexpected OK value returned"),
            Err(e) => {
                assert_eq!(e.code(), Code::Internal);
                assert_eq!(
                e.message(),
                "Attestation Bind Key Error: Could not unmarshall EK: response code not recognized"
            );
            }
        }
    }
    //
    // TODO: test_bind_attest_key_get_insert_pubkey_fails_returns_error - not clear how to simulate db failure atm

    // attestation as it is sent from scout to carbide
    const ATTEST_SERIALIZED: [u8; 129] = [
        255, 84, 67, 71, 128, 24, 0, 34, 0, 11, 86, 42, 234, 64, 215, 49, 217, 219, 109, 205, 122,
        208, 153, 128, 198, 122, 187, 249, 193, 120, 148, 109, 228, 44, 171, 165, 86, 18, 16, 178,
        17, 220, 0, 16, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 0, 0, 0, 1, 118, 32, 151, 182, 0, 0, 0, 63, 0, 0, 0, 0, 1, 0, 7, 0, 2, 0, 2, 0, 0, 0,
        0, 0, 1, 0, 11, 3, 255, 15, 0, 0, 32, 69, 159, 141, 33, 201, 110, 233, 102, 224, 171, 155,
        67, 115, 214, 128, 145, 55, 215, 242, 130, 251, 89, 92, 188, 251, 113, 20, 127, 251, 198,
        74, 188,
    ];

    // signature as it is sent from scout to carbide
    const SIGNATURE_SERIALIZED: [u8; 262] = [
        0, 22, 0, 11, 1, 0, 81, 47, 118, 82, 6, 100, 40, 191, 204, 125, 109, 165, 201, 104, 63, 55,
        190, 54, 157, 161, 149, 95, 179, 235, 130, 34, 255, 195, 134, 255, 28, 166, 232, 247, 140,
        130, 213, 211, 99, 25, 25, 240, 112, 230, 100, 109, 68, 125, 145, 170, 105, 12, 15, 157,
        32, 98, 220, 219, 166, 143, 22, 175, 150, 227, 155, 218, 150, 173, 252, 37, 225, 8, 88, 3,
        250, 157, 46, 94, 228, 55, 56, 118, 144, 72, 17, 10, 105, 12, 36, 25, 192, 104, 38, 3, 171,
        22, 125, 222, 96, 39, 56, 113, 218, 237, 205, 131, 201, 237, 212, 233, 188, 29, 1, 50, 75,
        122, 147, 104, 251, 243, 75, 183, 104, 200, 150, 72, 237, 213, 2, 124, 53, 65, 94, 85, 241,
        90, 10, 217, 90, 17, 142, 103, 208, 139, 205, 237, 240, 249, 23, 106, 187, 143, 17, 242,
        205, 200, 6, 34, 128, 162, 77, 65, 128, 100, 135, 77, 242, 49, 0, 119, 248, 215, 85, 151,
        245, 162, 227, 209, 200, 160, 255, 172, 79, 209, 183, 215, 77, 229, 87, 144, 73, 122, 170,
        254, 109, 80, 16, 57, 98, 50, 139, 248, 70, 215, 91, 85, 7, 28, 201, 201, 201, 37, 6, 147,
        211, 157, 130, 39, 37, 93, 86, 186, 88, 157, 8, 91, 101, 62, 69, 79, 36, 204, 224, 84, 67,
        168, 149, 120, 67, 86, 26, 157, 233, 168, 30, 69, 134, 181, 227, 106, 220, 218, 166, 242,
        45, 93,
    ];

    const SIGNATURE_SERIALIZED_INVALID: [u8; 262] = [
        0, 22, 0, 11, 1, 0, 171, 33, 190, 68, 89, 71, 190, 125, 172, 120, 100, 63, 101, 236, 168,
        171, 90, 209, 161, 89, 156, 193, 87, 74, 57, 203, 179, 84, 240, 213, 128, 158, 39, 132,
        212, 18, 25, 113, 53, 71, 255, 68, 15, 213, 40, 25, 118, 180, 156, 67, 63, 153, 150, 17,
        64, 74, 68, 242, 195, 11, 53, 92, 103, 222, 109, 66, 104, 115, 86, 243, 49, 31, 229, 160,
        71, 213, 45, 119, 126, 183, 106, 235, 224, 63, 132, 119, 208, 158, 236, 201, 147, 200, 70,
        166, 175, 20, 239, 145, 228, 215, 233, 184, 111, 54, 134, 133, 28, 171, 118, 94, 99, 43,
        194, 122, 19, 20, 107, 214, 203, 72, 16, 71, 16, 58, 116, 98, 64, 156, 197, 241, 184, 76,
        197, 198, 79, 15, 90, 157, 18, 234, 35, 241, 144, 136, 72, 69, 197, 232, 251, 251, 181,
        190, 64, 191, 130, 160, 76, 253, 179, 172, 12, 7, 213, 245, 140, 109, 97, 222, 164, 233,
        189, 166, 219, 218, 243, 72, 95, 124, 184, 71, 152, 109, 101, 47, 119, 117, 141, 1, 1, 108,
        148, 28, 69, 217, 177, 187, 153, 119, 216, 76, 44, 102, 249, 94, 56, 93, 108, 7, 229, 79,
        75, 47, 82, 82, 159, 202, 238, 240, 176, 99, 123, 61, 186, 28, 149, 166, 124, 62, 176, 84,
        197, 231, 222, 116, 40, 39, 68, 228, 210, 208, 152, 50, 240, 53, 223, 9, 213, 255, 190,
        231, 214, 11, 126, 155, 19, 190,
    ];

    // credential as it is sent from scout to carbide
    const CRED_SERIALIZED: [u8; 32] = [
        47, 191, 142, 91, 237, 86, 32, 168, 119, 196, 199, 149, 110, 183, 182, 192, 193, 99, 101,
        208, 107, 198, 254, 254, 10, 146, 61, 122, 138, 2, 82, 79,
    ];

    // pcr values as those are sent from scout to carbide
    const PCR_VALUES: [[u8; 32]; 12] = [
        [
            164, 126, 4, 71, 192, 152, 159, 113, 199, 82, 135, 160, 29, 112, 174, 109, 44, 162, 41,
            122, 116, 248, 9, 60, 82, 184, 5, 170, 14, 216, 205, 85,
        ],
        [
            194, 184, 135, 178, 147, 136, 167, 102, 146, 89, 65, 45, 32, 200, 40, 3, 203, 165, 253,
            191, 25, 109, 184, 243, 196, 215, 170, 188, 187, 77, 188, 218,
        ],
        [
            193, 20, 120, 210, 17, 121, 15, 237, 131, 254, 240, 142, 201, 223, 137, 40, 127, 152,
            151, 201, 86, 65, 123, 108, 214, 208, 253, 40, 199, 6, 186, 14,
        ],
        [
            61, 69, 140, 254, 85, 204, 3, 234, 31, 68, 63, 21, 98, 190, 236, 141, 245, 28, 117,
            225, 74, 159, 207, 154, 114, 52, 161, 63, 25, 142, 121, 105,
        ],
        [
            54, 29, 138, 144, 34, 133, 229, 109, 235, 18, 189, 32, 27, 118, 159, 87, 239, 21, 214,
            6, 94, 134, 22, 217, 13, 102, 96, 227, 91, 75, 201, 105,
        ],
        [
            34, 193, 24, 132, 113, 177, 222, 184, 127, 190, 135, 165, 107, 89, 26, 228, 171, 28,
            190, 33, 100, 152, 163, 231, 16, 102, 191, 62, 249, 103, 91, 235,
        ],
        [
            61, 69, 140, 254, 85, 204, 3, 234, 31, 68, 63, 21, 98, 190, 236, 141, 245, 28, 117,
            225, 74, 159, 207, 154, 114, 52, 161, 63, 25, 142, 121, 105,
        ],
        [
            89, 252, 9, 250, 212, 63, 169, 82, 124, 51, 102, 184, 32, 209, 249, 6, 131, 146, 231,
            49, 153, 40, 149, 164, 249, 101, 71, 133, 195, 0, 18, 143,
        ],
        [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ],
        [
            188, 142, 221, 92, 34, 86, 131, 100, 127, 248, 194, 106, 130, 144, 121, 202, 150, 176,
            167, 15, 93, 82, 93, 56, 194, 248, 41, 154, 110, 90, 230, 118,
        ],
        [
            200, 178, 20, 112, 5, 43, 67, 200, 183, 151, 1, 204, 18, 52, 80, 93, 155, 157, 78, 41,
            20, 211, 120, 174, 206, 220, 162, 162, 151, 67, 241, 175,
        ],
        [
            229, 31, 88, 234, 165, 46, 59, 155, 7, 0, 86, 10, 54, 122, 7, 39, 243, 23, 126, 117,
            71, 151, 2, 167, 175, 95, 121, 145, 192, 203, 204, 165,
        ],
    ];

    #[sqlx::test(fixtures("create_cred_pub_key.sql"))]
    async fn test_verify_quote_no_secret_in_db_returns_error(pool: sqlx::PgPool) {
        let env = create_test_env(pool).await;
        let host_id =
            MachineId::from_str("fm100hseddco33hvlofuqvg543p6p9aj60g76q5cq491g9m9tgtf2dk0530")
                .unwrap();

        let mut cred_serialized_invalid = CRED_SERIALIZED;
        cred_serialized_invalid[3] = 8; // corrupt the db key

        let request = tonic::Request::new(VerifyQuoteRequest {
            attestation: ATTEST_SERIALIZED.to_vec(),
            signature: SIGNATURE_SERIALIZED.to_vec(),
            credential: Vec::from(cred_serialized_invalid),
            pcr_values: PCR_VALUES.iter().map(|x| x.to_vec()).collect(),
            machine_id: Some(host_id.to_string().into()),
            event_log: None,
        });

        let res = env.api.verify_quote(request).await;

        match res {
            Ok(..) => panic!("Failed: should have returned an error"),
            Err(e) => {
                assert_eq!(e.code(), Code::Internal);
                assert_eq!(
                    e.message(),
                    "Attestation Verify Quote Error: Could not form SQL query to fetch AK Pub"
                );
            }
        }
    }

    #[sqlx::test(fixtures("create_cred_pub_key_invalid.sql"))]
    async fn test_verify_quote_invalid_ak_pub_in_db_returns_error(pool: sqlx::PgPool) {
        let env = create_test_env(pool).await;
        let host_id =
            MachineId::from_str("fm100hseddco33hvlofuqvg543p6p9aj60g76q5cq491g9m9tgtf2dk0530")
                .unwrap();

        let request = tonic::Request::new(VerifyQuoteRequest {
            attestation: ATTEST_SERIALIZED.to_vec(),
            signature: SIGNATURE_SERIALIZED.to_vec(),
            credential: Vec::from(CRED_SERIALIZED),
            pcr_values: PCR_VALUES.iter().map(|x| x.to_vec()).collect(),
            machine_id: Some(host_id.to_string().into()),
            event_log: None,
        });

        let res = env.api.verify_quote(request).await;

        match res {
            Ok(..) => panic!("Failed: should have returned an error"),
            Err(e) => {
                assert_eq!(e.code(), Code::Internal);
                assert_eq!(e.message(), "Attestation Verify Quote Error: Could not unmarshal AK Pub: response code not recognized");
            }
        }
    }

    #[sqlx::test(fixtures("create_cred_pub_key.sql"))]
    async fn test_verify_quote_cannot_unmarshall_attest_returns_error(pool: sqlx::PgPool) {
        let env = create_test_env(pool).await;
        let host_id =
            MachineId::from_str("fm100hseddco33hvlofuqvg543p6p9aj60g76q5cq491g9m9tgtf2dk0530")
                .unwrap();

        let mut attest_invalid = ATTEST_SERIALIZED;
        attest_invalid[5] = 54;

        let request = tonic::Request::new(VerifyQuoteRequest {
            attestation: attest_invalid.to_vec(),
            signature: SIGNATURE_SERIALIZED.to_vec(),
            credential: Vec::from(CRED_SERIALIZED),
            pcr_values: PCR_VALUES.iter().map(|x| x.to_vec()).collect(),
            machine_id: Some(host_id.to_string().into()),
            event_log: None,
        });

        let res = env.api.verify_quote(request).await;

        match res {
            Ok(..) => panic!("Failed: should have returned an error"),
            Err(e) => {
                assert_eq!(e.code(), Code::Internal);
                assert_eq!(e.message(), "Attestation Verify Quote Error: Could not unmarshall Attest struct: not currently used");
            }
        }
    }

    #[sqlx::test(fixtures("create_cred_pub_key.sql"))]
    async fn test_verify_quote_cannot_unmarshall_signature_returns_error(pool: sqlx::PgPool) {
        let env = create_test_env(pool).await;
        let host_id =
            MachineId::from_str("fm100hseddco33hvlofuqvg543p6p9aj60g76q5cq491g9m9tgtf2dk0530")
                .unwrap();

        let mut signature_invalid = SIGNATURE_SERIALIZED;
        signature_invalid[5] = 15;

        let request = tonic::Request::new(VerifyQuoteRequest {
            attestation: ATTEST_SERIALIZED.to_vec(),
            signature: signature_invalid.to_vec(),
            credential: Vec::from(CRED_SERIALIZED),
            pcr_values: PCR_VALUES.iter().map(|x| x.to_vec()).collect(),
            machine_id: Some(host_id.to_string().into()),
            event_log: None,
        });

        let res = env.api.verify_quote(request).await;

        match res {
            Ok(..) => panic!("Failed: should have returned an error"),
            Err(e) => {
                assert_eq!(e.code(), Code::Internal);
                assert_eq!(e.message(), "Attestation Verify Quote Error: Could not unmarshall Signature struct: response code not recognized");
            }
        }
    }

    #[cfg(feature = "tss-esapi")]
    #[sqlx::test(fixtures("create_cred_pub_key.sql"))]
    async fn test_verify_quote_cannot_verify_signature_fails_returns_error(pool: sqlx::PgPool) {
        use tss_esapi::structures::Signature;
        use tss_esapi::structures::Signature::RsaPss;
        use tss_esapi::structures::Signature::RsaSsa;
        use tss_esapi::traits::Marshall;
        use tss_esapi::traits::UnMarshall;

        let env = create_test_env(pool).await;
        let host_id =
            MachineId::from_str("fm100hseddco33hvlofuqvg543p6p9aj60g76q5cq491g9m9tgtf2dk0530")
                .unwrap();

        let signature = Signature::unmarshall(&SIGNATURE_SERIALIZED).unwrap();

        let rsa_signature = match signature {
            RsaPss(rsa_signature) => rsa_signature,
            _ => panic!("Failed: Unexepected signarue type in test"),
        };

        let signature_invalid = RsaSsa(rsa_signature);

        let request = tonic::Request::new(VerifyQuoteRequest {
            attestation: ATTEST_SERIALIZED.to_vec(),
            signature: Signature::marshall(&signature_invalid).unwrap(),
            credential: Vec::from(CRED_SERIALIZED),
            pcr_values: PCR_VALUES.iter().map(|x| x.to_vec()).collect(),
            machine_id: Some(host_id.to_string().into()),
            event_log: None,
        });

        let res = env.api.verify_quote(request).await;

        match res {
            Ok(..) => panic!("Failed: should have returned an error"),
            Err(e) => {
                assert_eq!(e.code(), Code::Internal);
                assert_eq!(
                    e.message(),
                    "Attestation Verify Quote Error: unknown signature type"
                );
            }
        }
    }

    // test_verify_quote_cannot_verify_pcr_hash_fails_returns_error - currently impossible to do since attest fields are private

    #[sqlx::test(fixtures("create_cred_pub_key.sql"))]
    async fn test_verify_quote_signature_mismatch_returns_false(pool: sqlx::PgPool) {
        let env = create_test_env(pool).await;
        let host_id =
            MachineId::from_str("fm100hseddco33hvlofuqvg543p6p9aj60g76q5cq491g9m9tgtf2dk0530")
                .unwrap();

        let request = tonic::Request::new(VerifyQuoteRequest {
            attestation: ATTEST_SERIALIZED.to_vec(),
            signature: SIGNATURE_SERIALIZED_INVALID.to_vec(), // invalid signature
            credential: Vec::from(CRED_SERIALIZED),
            pcr_values: PCR_VALUES.iter().map(|x| x.to_vec()).collect(),
            machine_id: Some(host_id.to_string().into()),
            event_log: None,
        });

        let res = env.api.verify_quote(request).await;

        match res {
            Ok(..) => panic!("Failed: should have returned an error"),
            Err(e) => {
                assert_eq!(e.code(), Code::Internal);
                assert_eq!(e.message(), "Attestation Verify Quote Error: PCR signature invalid (see logs for full event log)");
            }
        }
    }

    #[sqlx::test(fixtures("create_cred_pub_key.sql"))]
    async fn test_verify_quote_pcr_hash_mismatch_returns_false(pool: sqlx::PgPool) {
        let env = create_test_env(pool).await;
        let host_id =
            MachineId::from_str("fm100hseddco33hvlofuqvg543p6p9aj60g76q5cq491g9m9tgtf2dk0530")
                .unwrap();

        let mut pcr_values_invalid = PCR_VALUES;

        pcr_values_invalid[0][3] = 88; // corrupt the pcr values

        let request = tonic::Request::new(VerifyQuoteRequest {
            attestation: ATTEST_SERIALIZED.to_vec(),
            signature: SIGNATURE_SERIALIZED.to_vec(),
            credential: Vec::from(CRED_SERIALIZED),
            pcr_values: pcr_values_invalid.iter().map(|x| x.to_vec()).collect(),
            machine_id: Some(host_id.to_string().into()),
            event_log: None,
        });

        let res = env.api.verify_quote(request).await;

        match res {
            Ok(..) => panic!("Failed: should have returned an error"),
            Err(e) => {
                assert_eq!(e.code(), Code::Internal);
                assert_eq!(e.message(), "Attestation Verify Quote Error: PCR hash does not match (see logs for full event log)");
            }
        }
    }

    #[sqlx::test(fixtures("create_cred_pub_key.sql"))]
    async fn test_verify_quote_signature_and_pcr_hash_mismatch_returns_false(pool: sqlx::PgPool) {
        let env = create_test_env(pool).await;
        let host_id =
            MachineId::from_str("fm100hseddco33hvlofuqvg543p6p9aj60g76q5cq491g9m9tgtf2dk0530")
                .unwrap();

        let mut pcr_values_invalid = PCR_VALUES;

        pcr_values_invalid[0][3] = 88; // corrupt the pcr values

        let request = tonic::Request::new(VerifyQuoteRequest {
            attestation: ATTEST_SERIALIZED.to_vec(),
            signature: SIGNATURE_SERIALIZED_INVALID.to_vec(), // invalid signature
            credential: Vec::from(CRED_SERIALIZED),
            pcr_values: pcr_values_invalid.iter().map(|x| x.to_vec()).collect(),
            machine_id: Some(host_id.to_string().into()),
            event_log: None,
        });

        let res = env.api.verify_quote(request).await;

        match res {
            Ok(..) => panic!("Failed: should have returned an error"),
            Err(e) => {
                assert_eq!(e.code(), Code::Internal);
                assert_eq!(e.message(), "Attestation Verify Quote Error: PCR signature invalid and PCR hash mismatch (see logs for full event log)");
            }
        }
    }
}
