/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use std::cmp::min;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, de};

pub const DEFAULT_PAGE_RECORD_LIMIT: usize = 50;
const MAX_PAGE_RECORD_LIMIT: usize = 100;

/// Serde deserialization decorator to map empty Strings to None.
pub fn empty_string_as_none<'de, D, T>(de: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: FromStr,
    T::Err: fmt::Display,
{
    let opt = Option::<String>::deserialize(de)?;
    match opt.as_deref() {
        None | Some("") => Ok(None),
        Some(s) => FromStr::from_str(s).map_err(de::Error::custom).map(Some),
    }
}

#[derive(Deserialize, Debug, Default)]
pub struct PaginationParams {
    #[serde(default, deserialize_with = "empty_string_as_none")]
    pub limit: Option<usize>,
    #[serde(default, deserialize_with = "empty_string_as_none")]
    pub current_page: Option<usize>,
}

pub struct PaginationInfo {
    pub current_page: usize,
    pub limit: usize,
    pub total_items: usize,
}

impl PaginationInfo {
    pub fn pages(&self) -> usize {
        if self.limit == 0 {
            if self.total_items == 0 { 0 } else { 1 }
        } else {
            self.total_items.div_ceil(self.limit)
        }
    }

    pub fn previous(&self) -> usize {
        self.current_page.saturating_sub(1)
    }

    pub fn next(&self) -> usize {
        self.current_page.saturating_add(1)
    }

    pub fn page_range_start(&self) -> usize {
        self.current_page.saturating_sub(3)
    }

    pub fn page_range_end(&self) -> usize {
        min(self.current_page.saturating_add(4), self.pages())
    }
}

/// Shared pagination context for Askama templates. Embeds `PaginationInfo` and
/// adds the URL path and extra query parameters needed to render page links.
pub struct PageContext {
    info: PaginationInfo,
    pub path: String,
    pub extra_query_params: String,
}

impl PageContext {
    pub fn new(info: PaginationInfo, path: impl Into<String>) -> Self {
        Self {
            info,
            path: path.into(),
            extra_query_params: String::new(),
        }
    }

    /// Create a PageContext from a pre-computed page count (for handlers that
    /// perform database-level pagination and don't know the total item count).
    pub fn from_page_count(
        current_page: usize,
        limit: usize,
        pages: usize,
        path: impl Into<String>,
    ) -> Self {
        Self {
            info: PaginationInfo {
                current_page,
                limit,
                total_items: pages.saturating_mul(limit),
            },
            path: path.into(),
            extra_query_params: String::new(),
        }
    }

    pub fn with_extra_params(mut self, extra: String) -> Self {
        self.extra_query_params = extra;
        self
    }

    pub fn current_page(&self) -> usize {
        self.info.current_page
    }

    pub fn limit(&self) -> usize {
        self.info.limit
    }

    pub fn total_items(&self) -> usize {
        self.info.total_items
    }

    pub fn pages(&self) -> usize {
        self.info.pages()
    }

    pub fn previous(&self) -> usize {
        self.info.previous()
    }

    pub fn next(&self) -> usize {
        self.info.next()
    }

    pub fn page_range_start(&self) -> usize {
        self.info.page_range_start()
    }

    pub fn page_range_end(&self) -> usize {
        self.info.page_range_end()
    }
}

/// Resolve raw pagination params into a concrete `current_page` and `limit`.
fn resolve_params(params: &PaginationParams) -> (usize, usize) {
    let current_page = params.current_page.unwrap_or(0);
    let limit = params
        .limit
        .map_or(DEFAULT_PAGE_RECORD_LIMIT, |l| min(l, MAX_PAGE_RECORD_LIMIT));
    (current_page, limit)
}

/// Paginate a slice of IDs. Returns pagination metadata and the IDs for the
/// requested page. The caller should then batch-fetch details for only these IDs.
#[allow(dead_code)]
pub fn paginate_ids<T: Clone>(
    all_ids: &[T],
    params: &PaginationParams,
) -> (PaginationInfo, Vec<T>) {
    let (current_page, limit) = resolve_params(params);
    let total_items = all_ids.len();
    let info = PaginationInfo {
        current_page,
        limit,
        total_items,
    };

    if limit == 0 {
        return (info, all_ids.to_vec());
    }

    let offset = current_page.saturating_mul(limit);
    if offset >= total_items {
        return (info, vec![]);
    }

    let page_ids: Vec<T> = all_ids.iter().skip(offset).take(limit).cloned().collect();
    (info, page_ids)
}

/// Paginate an already-collected Vec (e.g. after in-memory filtering).
/// Drains elements outside the page window so only the current page remains.
pub fn paginate_vec<T>(items: Vec<T>, params: &PaginationParams) -> (PaginationInfo, Vec<T>) {
    let (current_page, limit) = resolve_params(params);
    let total_items = items.len();
    let info = PaginationInfo {
        current_page,
        limit,
        total_items,
    };

    if limit == 0 {
        return (info, items);
    }

    let offset = current_page.saturating_mul(limit);
    if offset >= total_items {
        return (info, vec![]);
    }

    let page_items: Vec<T> = items.into_iter().skip(offset).take(limit).collect();
    (info, page_items)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIMIT: usize = 1;

    #[test]
    fn paginate_ids_first_page() {
        let ids: Vec<i32> = (0..5).collect();
        let params = PaginationParams {
            current_page: Some(0),
            limit: Some(LIMIT),
        };
        let (info, page) = paginate_ids(&ids, &params);
        assert_eq!(page.len(), LIMIT);
        assert_eq!(page[0], 0);
        assert_eq!(info.pages(), 5);
        assert_eq!(info.total_items, 5);
    }

    #[test]
    fn paginate_ids_last_page() {
        let ids: Vec<i32> = (0..5).collect();
        let params = PaginationParams {
            current_page: Some(4),
            limit: Some(LIMIT),
        };
        let (info, page) = paginate_ids(&ids, &params);
        assert_eq!(page.len(), LIMIT);
        assert_eq!(page[0], 4);
        assert_eq!(info.pages(), 5);
    }

    #[test]
    fn paginate_ids_beyond_range() {
        let ids: Vec<i32> = (0..5).collect();
        let params = PaginationParams {
            current_page: Some(10),
            limit: Some(LIMIT),
        };
        let (info, page) = paginate_ids(&ids, &params);
        assert!(page.is_empty());
        assert_eq!(info.pages(), 5);
        assert_eq!(info.total_items, 5);
    }

    #[test]
    fn paginate_ids_limit_zero_returns_all() {
        let ids: Vec<i32> = (0..5).collect();
        let params = PaginationParams {
            current_page: None,
            limit: Some(0),
        };
        let (info, page) = paginate_ids(&ids, &params);
        assert_eq!(page.len(), 5);
        assert_eq!(info.pages(), 1);
        assert_eq!(info.total_items, 5);
    }

    #[test]
    fn paginate_ids_defaults() {
        let ids: Vec<i32> = (0..5).collect();
        let params = PaginationParams {
            current_page: None,
            limit: None,
        };
        let (info, page) = paginate_ids(&ids, &params);
        assert_eq!(page.len(), 5);
        assert_eq!(info.pages(), 1);
        assert_eq!(info.limit, DEFAULT_PAGE_RECORD_LIMIT);
        assert_eq!(info.current_page, 0);
    }

    #[test]
    fn paginate_vec_with_filter() {
        let items: Vec<i32> = (0..5).collect();
        let params = PaginationParams {
            current_page: Some(1),
            limit: Some(LIMIT),
        };
        let (info, page) = paginate_vec(items, &params);
        assert_eq!(page.len(), LIMIT);
        assert_eq!(page[0], 1);
        assert_eq!(info.pages(), 5);
        assert_eq!(info.total_items, 5);
    }

    #[test]
    fn paginate_empty() {
        let ids: Vec<i32> = vec![];
        let params = PaginationParams {
            current_page: None,
            limit: None,
        };
        let (info, page) = paginate_ids(&ids, &params);
        assert!(page.is_empty());
        assert_eq!(info.pages(), 0);
        assert_eq!(info.total_items, 0);
    }
}
