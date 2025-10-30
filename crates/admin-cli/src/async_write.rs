/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

/// Macro for writing formatted output to a tokio::io::AsyncWrite object
/// Similar to write! but for async writers
/// $writer must be AsyncWrite + Pin
#[macro_export]
macro_rules! async_write {
    ($writer:expr, $($arg:tt)*) => {
        {
            use tokio::io::AsyncWriteExt;
            let formatted = format!($($arg)*);
            let mut result = $writer.write_all(formatted.as_bytes()).await;
            if result.is_ok() {
                let flush_result = $writer.flush().await;
                if flush_result.is_err() {
                    result = flush_result;
                }
            }
            result
        }
    };
}

/// Macro for writing formatted output with a newline to a tokio::io::AsyncWrite object
/// Similar to writeln! but for async writers
/// $writer must be AsyncWrite + Pin
#[macro_export]
macro_rules! async_writeln {
    ($writer:expr) => {{
        use tokio::io::AsyncWriteExt;
        $writer.write_all("\n".as_bytes()).await
    }};
    ($writer:expr, $($arg:tt)+) => {{
        use tokio::io::AsyncWriteExt;
        let mut formatted = format!($($arg)+);
        formatted.push('\n');
        let mut result = $writer.write_all(formatted.as_bytes()).await;
        if result.is_ok() {
            let flush_result = $writer.flush().await;
            if flush_result.is_err() {
                result = flush_result;
            }
        }
        result
    }};
}

/// Macro for writing a prettytable table as csv to a tokio::io::AsyncWrite object
/// $writer must be AsyncWrite + Pin
#[macro_export]
macro_rules! async_write_table_as_csv {
    ($writer:expr, $table:expr) => {{
        use tokio::io::AsyncWriteExt;
        let mut output = Vec::default();
        $table
            .to_csv(&mut output)
            .map_err(|e| CarbideCliError::GenericError(e.to_string()))?;
        let mut result = $writer.write_all(output.as_slice()).await;
        if result.is_ok() {
            let flush_result = $writer.flush().await;
            if flush_result.is_err() {
                result = flush_result;
            }
        }
        result
    }};
}
