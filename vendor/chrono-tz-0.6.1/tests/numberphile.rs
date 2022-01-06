//! Unit tests derived from Tom Scott's video on Numberphile,
//! [`The Problem with Time & Timezones'][video].
//! Note that not all tests are passing; the ones towards
//! the end of the video are not handled correctly (nor are
//! currently intended to be handled correctly) by chrono.
//!
//! [video]: https://www.youtube.com/watch?v=-5wpm-gesOY

extern crate chrono;
extern crate chrono_tz;

use chrono::{DateTime, TimeZone};

use chrono_tz::Africa::Tripoli;
use chrono_tz::America::New_York;
use chrono_tz::Asia::Gaza;
use chrono_tz::Asia::Jerusalem;
use chrono_tz::Asia::Kathmandu;
use chrono_tz::Australia::Adelaide;
use chrono_tz::Etc::UTC;
use chrono_tz::Europe::London;
use chrono_tz::Europe::Moscow;
use chrono_tz::Pacific::Apia;

fn seconds<Tz1: TimeZone, Tz2: TimeZone>(from: DateTime<Tz1>, to: DateTime<Tz2>) -> i64 {
    to.signed_duration_since(from).num_seconds()
}

#[test]
fn london_5_days_ago_to_new_york() {
    let from = London.ymd(2013, 12, 25).and_hms(14, 0, 0);
    let to = New_York.ymd(2013, 12, 30).and_hms(14, 0, 0);
    assert_eq!(seconds(from, to), 60 * 60 * (24 * 5 + 5));
}

#[test]
fn london_to_australia() {
    // at the time Tom was speaking, Adelaide was 10 1/2 hours ahead
    // many other parts of Australia use different time zones
    let from = London.ymd(2013, 12, 25).and_hms(14, 0, 0);
    let to = Adelaide.ymd(2013, 12, 30).and_hms(14, 0, 0);
    assert_eq!(seconds(from, to), 60 * 60 * (24 * 5 - 10) - 60 * 30);
}

#[test]
fn london_to_nepal() {
    // note Tom gets this wrong, it's 5 3/4 hours as he is speaking
    let from = London.ymd(2013, 12, 25).and_hms(14, 0, 0);
    let to = Kathmandu.ymd(2013, 12, 30).and_hms(14, 0, 0);
    assert_eq!(seconds(from, to), 60 * 60 * (24 * 5 - 5) - 60 * 45);
}

#[test]
fn autumn() {
    let from = London.ymd(2013, 10, 25).and_hms(12, 0, 0);
    let to = London.ymd(2013, 11, 1).and_hms(12, 0, 0);
    assert_eq!(seconds(from, to), 60 * 60 * (24 * 7 + 1));
}

#[test]
fn earlier_daylight_savings_in_new_york() {
    let from = New_York.ymd(2013, 10, 25).and_hms(12, 0, 0);
    let to = New_York.ymd(2013, 11, 1).and_hms(12, 0, 0);
    assert_eq!(seconds(from, to), 60 * 60 * (24 * 7));
}

#[test]
fn southern_hemisphere_clocks_forward() {
    let from = Adelaide.ymd(2013, 10, 1).and_hms(12, 0, 0);
    let to = Adelaide.ymd(2013, 11, 1).and_hms(12, 0, 0);
    assert_eq!(seconds(from, to), 60 * 60 * (24 * 31 - 1));
}

#[test]
fn samoa_skips_a_day() {
    let from = Apia.ymd(2011, 12, 29).and_hms(12, 0, 0);
    let to = Apia.ymd(2011, 12, 31).and_hms(12, 0, 0);
    assert_eq!(seconds(from, to), 60 * 60 * 24);
}

#[test]
fn double_bst() {
    let from = London.ymd(1942, 6, 1).and_hms(12, 0, 0);
    let to = UTC.ymd(1942, 6, 1).and_hms(12, 0, 0);
    assert_eq!(seconds(from, to), 60 * 60 * 2);
}

#[test]
fn libya_2013() {
    // Libya actually put their clocks *forward* in 2013, but not in any other year
    let from = Tripoli.ymd(2012, 3, 1).and_hms(12, 0, 0);
    let to = Tripoli.ymd(2012, 4, 1).and_hms(12, 0, 0);
    assert_eq!(seconds(from, to), 60 * 60 * 24 * 31);

    let from = Tripoli.ymd(2013, 3, 1).and_hms(12, 0, 0);
    let to = Tripoli.ymd(2013, 4, 1).and_hms(12, 0, 0);
    assert_eq!(seconds(from, to), 60 * 60 * (24 * 31 - 1));

    let from = Tripoli.ymd(2014, 3, 1).and_hms(12, 0, 0);
    let to = Tripoli.ymd(2014, 4, 1).and_hms(12, 0, 0);
    assert_eq!(seconds(from, to), 60 * 60 * 24 * 31);
}

#[test]
fn israel_palestine() {
    let from = Jerusalem.ymd(2016, 10, 29).and_hms(12, 0, 0);
    let to = Gaza.ymd(2016, 10, 29).and_hms(12, 0, 0);
    assert_eq!(seconds(from, to), 60 * 60);
}

// FIXME doesn't currently work!
#[test]
#[ignore]
fn london_julian_to_gregorian() {
    let from = London.ymd(1752, 9, 2).and_hms(12, 0, 0);
    let to = London.ymd(1752, 9, 14).and_hms(12, 0, 0);
    assert_eq!(seconds(from, to), 60 * 60 * 24);
}

// FIXME doesn't currently work!
#[test]
#[ignore]
fn russian_julian_to_gregorian() {
    let from = Moscow.ymd(1918, 1, 31).and_hms(12, 0, 0);
    let to = Moscow.ymd(1918, 2, 14).and_hms(12, 0, 0);
    assert_eq!(seconds(from, to), 60 * 60 * 24);
}

// FIXME doesn't currently work!
#[test]
#[ignore]
fn london_25_march() {
    let from = London.ymd(924, 3, 24).and_hms(12, 0, 0);
    let to = London.ymd(925, 3, 25).and_hms(12, 0, 0);
    assert_eq!(seconds(from, to), 60 * 60 * 24);
}

#[test]
fn leapsecond() {
    let from = UTC.ymd(2016, 6, 30).and_hms(23, 59, 59);
    let to = UTC.ymd(2016, 6, 30).and_hms_milli(23, 59, 59, 1000);
    assert_eq!(seconds(from, to), 1);
}

// FIXME doesn't currently work!
#[test]
#[ignore]
fn leapsecond_2() {
    let from = UTC.ymd(2016, 6, 30).and_hms(23, 59, 59);
    let to = UTC.ymd(2016, 7, 1).and_hms(0, 0, 0);
    assert_eq!(seconds(from, to), 2);
}

// FIXME doesn't currently work!
#[test]
#[ignore]
fn leapsecond_3() {
    let from = UTC.ymd(2016, 6, 30).and_hms_milli(23, 59, 59, 1000);
    let to = UTC.ymd(2016, 7, 1).and_hms(0, 0, 0);
    assert_eq!(seconds(from, to), 1);
}
