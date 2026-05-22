//! Optional rekey audit lines (`-DTUNNEL_DEBUG` in C). Enable with `--features tunnel-debug`.

#[cfg(feature = "tunnel-debug")]
#[macro_export]
macro_rules! dbg_rekey {
    ($role:expr, $phase:expr, $epoch:expr, $count:expr) => {
        eprintln!(
            "{}: rekey {} epoch={} count={}",
            $role, $phase, $epoch, $count
        );
    };
}

#[cfg(not(feature = "tunnel-debug"))]
#[macro_export]
macro_rules! dbg_rekey {
    ($role:expr, $phase:expr, $epoch:expr, $count:expr) => {};
}
