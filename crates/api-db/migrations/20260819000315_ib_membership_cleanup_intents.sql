-- Keep exact desired-absence memberships after their Machine and Instance are
-- gone and after successful unbinds. Only later live presence supersedes them.
CREATE TABLE ib_membership_cleanup_intents (
    fabric TEXT NOT NULL,
    pkey INTEGER NOT NULL CHECK (pkey BETWEEN 0 AND 32767),
    guid TEXT NOT NULL,
    PRIMARY KEY (fabric, pkey, guid)
);
