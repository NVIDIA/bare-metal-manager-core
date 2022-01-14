Chrono-tz Changelog
===================

## 0.6.0

* **tzdb** [breaking change] Update tzdb to 2020b, which removes the `US/Pacific-New` timezone.
  https://github.com/eggert/tz/commit/284e877d7511d964249ecfd2e75a9cab85e2741a

* **feature** Add support for filtering the set of timezones with a new `filter-by-regex` feature
  which uses `CHRONO_TZ_TIMEZONE_FILTER` env var. It should be set to a regular expression of
  timezones to include.

* **feature** Add support for case-insensitive timezone matching via the `case-insensitive`
  feature.
