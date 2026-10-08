//! The session lane (0.3.4): `bsv_middleware_core::session_lane`, re-exported
//! whole at its 0.3 path. The rules are pure and live in the core; the store
//! (`storage::do_session`) and the door (`middleware::auth::process_auth_lane`)
//! wire them. The adapter keeps the lane's test suite and its vector fixture
//! (`tests/fixtures/session_lane.vectors.json`) as the proof that the
//! re-exported surface is the 0.3 surface, byte for byte.

pub use bsv_middleware_core::session_lane::*;
