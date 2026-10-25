//! Live child diagnostics and fail-fast summaries, adapted from Kedra.
use std::{
    fs::{self, File},
    io::{self, BufRead, BufReader, Write},
    path::PathBuf,
    time::{Duration, Instant},
};

pub(crate) struct Session {
    log: File,
    path: PathBuf,
    started: Instant,
    results: Vec<(&'static str, bool, Duration)>,
}

impl Session {
    pub fn new() -> crate::Result<Self> {
        let directory = PathBuf::from("target/xtask/logs");
        fs::create_dir_all(&directory)?;
        let (log, path) = tempfile::Builder::new()
            .prefix("run-")
            .suffix(".log")
            .tempfile_in(directory)?
            .keep()?;
        let mut session = Self {
            log,
            path,
            started: Instant::now(),
            results: Vec::new(),
        };
        session.message("NetworkManager Tunnel / repository checks")?;
        session.message(&format!("Log: {}", session.path.display()))?;
        Ok(session)
    }

    pub fn message(&mut self, message: &str) -> crate::Result<()> {
        writeln!(self.log, "{message}")?;
        self.log.flush()?;
        let mut stdout = io::stdout().lock();
        writeln!(stdout, "{message}")?;
        stdout.flush()?;
        Ok(())
    }

    pub fn stage(
        &mut self,
        index: usize,
        total: usize,
        label: &'static str,
        action: impl FnOnce(&mut Self) -> crate::Result<()>,
    ) -> crate::Result<()> {
        self.message(&format!("\n[{index}/{total}] {label}"))?;
        let started = Instant::now();
        let result = action(self);
        let duration = started.elapsed();
        self.results.push((label, result.is_ok(), duration));
        match &result {
            Ok(()) => self.message(&format!("PASS {label} ({:.2}s)", duration.as_secs_f64()))?,
            Err(error) => self.message(&format!("FAIL {label}: {error}"))?,
        }
        result
    }

    pub fn cargo(&mut self, args: &[&str], rustdoc: bool) -> crate::Result<()> {
        self.message(&format!("+ cargo {}", args.join(" ")))?;
        let mut command = duct::cmd("cargo", args)
            .stdin_null()
            .stderr_to_stdout()
            .env("CARGO_TERM_COLOR", "never");
        if rustdoc {
            command = command.env(
                "RUSTDOCFLAGS",
                "-D warnings -D rustdoc::broken_intra_doc_links",
            );
        }
        self.stream(command)
    }

    fn stream(&mut self, command: duct::Expression) -> crate::Result<()> {
        // Emit even an unterminated final diagnostic before validating exit status.
        let reader = command.unchecked().reader()?;
        let mut stream = BufReader::new(reader);
        let mut line = Vec::new();
        loop {
            line.clear();
            let read = stream.read_until(b'\n', &mut line);
            if !line.is_empty() {
                self.message(String::from_utf8_lossy(&line).trim_end_matches(['\r', '\n']))?;
            }
            if read? == 0 {
                break;
            }
        }
        let status = stream
            .get_ref()
            .try_wait()?
            .ok_or("child still running after EOF")?
            .status;
        if !status.success() {
            return Err(format!("child exited with {status}").into());
        }
        Ok(())
    }

    pub fn finish(&mut self, total: usize) -> crate::Result<()> {
        self.message("\nSummary")?;
        for (label, success, duration) in self.results.clone() {
            self.message(&format!(
                "  {} {label}: {:.2}s",
                if success { "PASS" } else { "FAIL" },
                duration.as_secs_f64()
            ))?;
        }
        let passed = self
            .results
            .iter()
            .filter(|(_, success, _)| *success)
            .count();
        self.message(&format!(
            "{passed} passed, {} failed, {} skipped; total {:.2}s",
            self.results.len() - passed,
            total - self.results.len(),
            self.started.elapsed().as_secs_f64()
        ))?;
        self.message(&format!("Log: {}", self.path.display()))
    }
}
