// The library half of the nsm-attest crate: the logic of nsm-timefeed
// (src/bin/nsm-timefeed.rs), kept out of the binary so it can be unit-tested.
// nsm-attest (src/main.rs) does not use it, so its contract is unchanged.
pub mod timefeed;
