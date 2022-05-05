use std::convert::{TryFrom, TryInto};

use chrono::prelude::*;
use sqlx::postgres::PgRow;
use sqlx::{Error, Postgres, Row, Transaction};
use uuid::Uuid;

use rpc::v0 as rpc;

use crate::db::UuidKeyedObjectFilter;
use crate::{CarbideError, CarbideResult};

#[derive(Clone, Debug)]
pub struct Tag {
    pub slug: String,
    pub name: Option<String>,
}

#[derive(Clone, Debug)]
pub struct TagCreate {
    pub tag: Option<Tag>,
}

#[derive(Clone, Debug)]
pub struct TagDelete {
    pub tag: Option<Tag>,
}

#[derive(Clone, Debug)]
pub struct TagResult {
    pub result: bool,
}

#[derive(Clone, Debug)]
pub struct TagsList {
}

#[derive(Clone, Debug)]
pub struct TagAssign {
    pub slug: String,
    pub target: String,
    pub target_kind: i32,
}

#[derive(Clone, Debug)]
pub struct TagRemove {
    pub slug: String,
    pub target: String,
    pub target_kind: i32,
}

impl<'r> sqlx::FromRow<'r, PgRow> for Tag {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        Ok(Tag {
            slug: row.try_get("slug")?,
            name: row.try_get("name")?,
        })
    }
}

impl Tag {
    pub async fn persist(&self, txn: &mut sqlx::Transaction<'_, Postgres>) -> CarbideResult<Tag> {
        Ok(
            sqlx::query_as("INSERT INTO tags (slug, name) VALUES ($1, $2) RETURNING *")
            .bind(&self.slug)
            .bind(&self.name)
            .fetch_one(&mut *txn)
            .await
            .map_err(|err: sqlx::Error| match err {
                _ => CarbideError::from(err),
            })?,
        )
    }

    pub async fn delete(&self, txn: &mut sqlx::Transaction<'_, Postgres>) -> CarbideResult<Tag> {
        Ok(
            sqlx::query_as("DELETE from tags WHERE slug=$1 RETURNING *")
            .bind(&self.slug)
            .fetch_one(&mut *txn)
            .await
            .map_err(|err: sqlx::Error| match err {
                _ => CarbideError::from(err),
            })?,
        )
    }

    pub async fn find_all(
        txn: &mut sqlx::Transaction<'_, Postgres>,
        ) -> CarbideResult<Vec<Tag>> {
        Ok(    
            sqlx::query_as("SELECT * FROM tags")
            .fetch_all(&mut *txn)
            .await
            .map_err(|err: sqlx::Error| match err {
                _ => CarbideError::from(err),
            })?,
        )
    }
}

impl TryFrom<rpc::TagCreate> for TagCreate {
    type Error = CarbideError;

    fn try_from(value: rpc::TagCreate) -> Result<Self, Self::Error> {
        if let Some(t) = value.tag {
            return Ok(TagCreate {
                tag: Some(
                        Tag {
                            name: t.name.to_owned(),
                            slug: t.slug.to_owned(),
                        }
                    )
            });
        }
        
        Err(CarbideError::GenericError("Tag value is not present in Tag Create request.".to_string()))
    }
}

impl TagCreate {
    pub async fn create(&self, txn: &mut sqlx::Transaction<'_, Postgres>) -> CarbideResult<rpc::TagResult> {
        match &self.tag {
            Some(tag_info) => {
                tag_info.persist(txn).await?;
                Ok(rpc::TagResult{result: true})
            },
            _ => Err(CarbideError::GenericError("Didn't get tag in create request.".to_string()))
        }
    }
}

impl TryFrom<rpc::TagDelete> for TagDelete {
    type Error = CarbideError;

    fn try_from(value: rpc::TagDelete) -> Result<Self, Self::Error> {
        if let Some(t) = value.tag {
            return Ok(TagDelete {
                tag: Some(
                        Tag {
                            name: t.name.to_owned(),
                            slug: t.slug.to_owned(),
                        }
                    )
            });
        }
        
        Err(CarbideError::GenericError("Tag value is not present in Tag Delete request.".to_string()))
    }
}

impl TagDelete {
    pub async fn delete(&self, txn: &mut sqlx::Transaction<'_, Postgres>) -> CarbideResult<rpc::TagResult> {
        match &self.tag {
            Some(tag_info) => {
                tag_info.delete(txn).await;
                Ok(rpc::TagResult{result: true})
            },
            _ => Err(CarbideError::GenericError("Didn't get tag in delete request.".to_string()))
        }
    }
}

impl TryFrom<rpc::TagsList> for TagsList {
    type Error = CarbideError;

    fn try_from(value: rpc::TagsList) -> Result<Self, Self::Error> {
        Ok(TagsList {})
    }
}

impl TagsList {
    pub async fn find_all(txn: &mut sqlx::Transaction<'_, Postgres>) -> CarbideResult<rpc::TagsListResult> {
        Ok(
            rpc::TagsListResult{
                tags: Tag::find_all(txn).await? 
                    .iter()
                    .map(move |t| rpc::Tag{slug: t.slug.to_owned(), name: t.name.to_owned()})
                    .collect::<Vec<rpc::Tag>>()
            }
          )
    }
}
