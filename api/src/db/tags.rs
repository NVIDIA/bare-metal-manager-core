use std::convert::TryFrom;

use sqlx::postgres::PgRow;
use sqlx::{Postgres, Row};
use uuid::Uuid;

use rpc::forge::v0 as rpc;

use crate::{CarbideError, CarbideResult};

#[derive(Clone, Debug)]
pub struct Tag {
    pub id: Option<Uuid>,
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
    pub slugs: Vec<String>,
    pub target: Uuid,
    pub target_kind: TagTargetKind,
}

#[derive(Clone, Debug)]
pub struct TagsListResult {
    pub tags: Vec<Tag>,
    pub error: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum TagTargetKind {
    Machine = 0,
    NetworkSegment = 1,
    Unknown = 0xff,
}

#[derive(Clone, Debug)]
pub struct TagAssociation {
    pub tag_id: Option<Uuid>,
    pub slug: Option<String>,
    pub target: Uuid,
    pub target_kind: TagTargetKind,
}

fn get_uuid(target_id: Option<rpc::Uuid>) -> Result<Uuid, CarbideError> {
    let rpc_uuid = target_id.ok_or(CarbideError::GenericError(format!(
        "Did not supply a valid Target id UUID",
    )))?;

    uuid::Uuid::try_from(rpc_uuid)
        .map_err(|err| CarbideError::GenericError(format!("Invalid id received, Error: {}.", err)))
}

fn int_to_target_kind(kind: i32) -> Result<TagTargetKind, CarbideError> {
    Ok(match kind {
        0 => TagTargetKind::Machine,
        1 => TagTargetKind::NetworkSegment,
        _ => {
            return Err(CarbideError::GenericError(format!(
                "Invalid {} target kind received.",
                kind
            )));
        }
    })
}

fn get_table_name(kind: TagTargetKind) -> String {
    format!("tags_{:?}", kind)
}

impl<'r> sqlx::FromRow<'r, PgRow> for Tag {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        Ok(Tag {
            id: row.try_get("id")?,
            slug: row.try_get("slug")?,
            name: row.try_get("name")?,
        })
    }
}

impl<'r> sqlx::FromRow<'r, PgRow> for TagAssociation {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        Ok(TagAssociation {
            tag_id: row.try_get("tag_id")?,
            slug: None,
            target: row.try_get("target_id")?,
            target_kind: TagTargetKind::Unknown,
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
        Ok(sqlx::query_as("DELETE from tags WHERE slug=$1 RETURNING *")
            .bind(&self.slug)
            .fetch_one(&mut *txn)
            .await
            .map_err(|err: sqlx::Error| match err {
                _ => CarbideError::from(err),
            })?)
    }

    pub async fn find_all(txn: &mut sqlx::Transaction<'_, Postgres>) -> CarbideResult<Vec<Tag>> {
        Ok(sqlx::query_as("SELECT * FROM tags")
            .fetch_all(&mut *txn)
            .await
            .map_err(|err: sqlx::Error| match err {
                _ => CarbideError::from(err),
            })?)
    }

    pub async fn find_one(
        txn: &mut sqlx::Transaction<'_, Postgres>,
        slug: String,
    ) -> CarbideResult<Vec<Tag>> {
        Ok(sqlx::query_as("SELECT * FROM tags where slug=$1")
            .bind(slug)
            .fetch_all(&mut *txn)
            .await
            .map_err(|err: sqlx::Error| match err {
                _ => CarbideError::from(err),
            })?)
    }

    pub async fn list_all(
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> CarbideResult<rpc::TagsListResult> {
        Ok(rpc::TagsListResult {
            tags: Tag::find_all(txn)
                .await?
                .iter()
                .map(move |t| rpc::Tag {
                    slug: t.slug.to_owned(),
                    name: t.name.to_owned(),
                })
                .collect::<Vec<rpc::Tag>>(),
        })
    }
}

impl TryFrom<rpc::TagCreate> for TagCreate {
    type Error = CarbideError;

    fn try_from(value: rpc::TagCreate) -> Result<Self, Self::Error> {
        if let Some(t) = value.tag {
            return Ok(TagCreate {
                tag: Some(Tag {
                    id: None,
                    name: t.name.to_owned(),
                    slug: t.slug.to_owned(),
                }),
            });
        }

        Err(CarbideError::GenericError(
            "Tag value is not present in Tag Create request.".to_string(),
        ))
    }
}

impl TagCreate {
    pub async fn create(
        &self,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> CarbideResult<rpc::TagResult> {
        match &self.tag {
            Some(tag_info) => {
                tag_info.persist(txn).await?;
                Ok(rpc::TagResult { result: true })
            }
            _ => Err(CarbideError::GenericError(
                "Didn't get tag in create request.".to_string(),
            )),
        }
    }
}

impl TryFrom<rpc::TagDelete> for TagDelete {
    type Error = CarbideError;

    fn try_from(value: rpc::TagDelete) -> Result<Self, Self::Error> {
        if let Some(t) = value.tag {
            return Ok(TagDelete {
                tag: Some(Tag {
                    id: None,
                    name: t.name.to_owned(),
                    slug: t.slug.to_owned(),
                }),
            });
        }

        Err(CarbideError::GenericError(
            "Tag value is not present in Tag Delete request.".to_string(),
        ))
    }
}

impl TagDelete {
    pub async fn delete(
        &self,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> CarbideResult<rpc::TagResult> {
        match &self.tag {
            Some(tag_info) => {
                tag_info.delete(txn).await?;
                Ok(rpc::TagResult { result: true })
            }
            _ => Err(CarbideError::GenericError(
                "Didn't get tag in delete request.".to_string(),
            )),
        }
    }
}

impl TryFrom<rpc::TagsList> for TagsList {
    type Error = CarbideError;

    fn try_from(value: rpc::TagsList) -> Result<Self, Self::Error> {
        Ok(TagsList {
            slugs: value.slugs.to_owned(),
            target: match value.target {
                Some(id) => match uuid::Uuid::try_from(id) {
                    Ok(uuid) => uuid,
                    Err(err) => {
                        return Err(CarbideError::GenericError(format!(
                            "Did not supply a valid Target id UUID: {}",
                            err
                        )));
                    }
                },
                None => {
                    return Err(CarbideError::GenericError(
                        "Did not receive a valid Target id UUID.".to_string(),
                    ));
                }
            },
            target_kind: int_to_target_kind(value.target_kind)?,
        })
    }
}

impl TagsList {
    pub async fn assign(
        &self,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> CarbideResult<rpc::TagResult> {
        TagAssociation::remove_all_slugs_from_target(txn, self.target, self.target_kind).await?;
        for slug in self.slugs.iter() {
            TagAssociation {
                tag_id: None,
                slug: Some(slug.clone()),
                target: self.target.clone(),
                target_kind: self.target_kind,
            }
            .assign(txn)
            .await?;
        }

        Ok(rpc::TagResult { result: true })
    }
}

impl TryFrom<rpc::TagAssign> for TagAssociation {
    type Error = CarbideError;

    fn try_from(value: rpc::TagAssign) -> Result<Self, Self::Error> {
        Ok(TagAssociation {
            tag_id: None,
            slug: Some(value.slug.to_owned()),
            target: get_uuid(value.target)?,
            target_kind: int_to_target_kind(value.target_kind)?,
        })
    }
}

impl TryFrom<rpc::TagRemove> for TagAssociation {
    type Error = CarbideError;

    fn try_from(value: rpc::TagRemove) -> Result<Self, Self::Error> {
        Ok(TagAssociation {
            tag_id: None,
            slug: Some(value.slug.to_owned()),
            target: get_uuid(value.target)?,
            target_kind: int_to_target_kind(value.target_kind)?,
        })
    }
}

impl TagAssociation {
    pub async fn remove_all_slugs_from_target(
        txn: &mut sqlx::Transaction<'_, Postgres>,
        target: Uuid,
        target_kind: TagTargetKind,
    ) -> CarbideResult<rpc::TagResult> {
        let table_name = get_table_name(target_kind);
        let query = "DELETE FROM {table} WHERE target_id=$1 RETURNING *";
        sqlx::query_as::<_, TagAssociation>(&query.replace("{table}", table_name.as_str()))
            .bind(target)
            .fetch_optional(&mut *txn)
            .await
            .map_err(|err: sqlx::Error| match err {
                _ => CarbideError::from(err),
            })?;

        Ok(rpc::TagResult { result: true })
    }

    pub async fn assign(
        &self,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> CarbideResult<rpc::TagResult> {
        let table_name = get_table_name(self.target_kind);
        let slug = (*(self
            .slug
            .as_ref()
            .ok_or(CarbideError::GenericError("Slug is missing.".to_string()))?))
        .to_string();
        let tag_id = Tag::find_one(txn, slug)
            .await?
            .first()
            .ok_or(CarbideError::GenericError(
                "Slug not found in db.".to_string(),
            ))?
            .id;

        let query = "INSERT INTO {table} (tag_id, target_id) VALUES ($1, $2) RETURNING *";
        sqlx::query_as::<_, TagAssociation>(&query.replace("{table}", table_name.as_str()))
            .bind(tag_id)
            .bind(&self.target)
            .fetch_one(&mut *txn)
            .await
            .map_err(|err: sqlx::Error| match err {
                _ => CarbideError::from(err),
            })?;

        Ok(rpc::TagResult { result: true })
    }

    pub async fn remove(
        &self,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> CarbideResult<rpc::TagResult> {
        let table_name = get_table_name(self.target_kind);
        let slug = (*(self
            .slug
            .as_ref()
            .ok_or(CarbideError::GenericError("Slug is missing.".to_string()))?))
        .to_string();

        let tag_id = Tag::find_one(txn, slug)
            .await?
            .first()
            .ok_or(CarbideError::GenericError(
                "Slug not found in db.".to_string(),
            ))?
            .id;

        let query = "DELETE FROM {table} WHERE tag_id=$1 AND target_id=$2 RETURNING *";
        sqlx::query_as::<_, TagAssociation>(&query.replace("{table}", table_name.as_str()))
            .bind(tag_id)
            .bind(&self.target)
            .fetch_optional(&mut *txn)
            .await
            .map_err(|err: sqlx::Error| match err {
                _ => CarbideError::from(err),
            })?;

        Ok(rpc::TagResult { result: true })
    }
}
