use rustls::time_provider::TimeProvider;
//use core::time::Duration;
use rustls::pki_types::UnixTime;

// Required for no_std
#[derive(Debug)]
pub(crate) struct FakeTime;

// TODO: Figure how to handle time
impl TimeProvider for FakeTime {
    fn current_time(&self) -> Option<UnixTime> {
        None
    }
}
