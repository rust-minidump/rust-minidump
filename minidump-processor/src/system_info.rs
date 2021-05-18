use minidump::system_info::{Cpu, Os};

/// Information about the system that produced a `Minidump`.
pub struct SystemInfo {
    /// The operating system that produced the minidump
    pub os: Os,
    /// A string identifying the version of the operating system
    ///
    /// This may look like "5.1.2600 Service Pack 2" or "10.4.8 8L2127", if present
    pub os_version: Option<String>,
    /// The CPU on which the dump was produced
    pub cpu: Cpu,
    /// A string further identifying the specific CPU
    ///
    /// For example,  "GenuineIntel level 6 model 13 stepping 8", if present.
    pub cpu_info: Option<String>,
    /// The number of processors in the system
    ///
    /// Will be greater than one for multi-core systems.
    pub cpu_count: usize,
}
