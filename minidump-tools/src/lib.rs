extern crate breakpad_symbols;
extern crate disasm;
extern crate env_logger;
#[macro_use]
extern crate failure;
#[macro_use]
extern crate log;
extern crate minidump;
extern crate reqwest;
#[macro_use]
extern crate structopt;

use breakpad_symbols::{SimpleFrame, SimpleSymbolSupplier, Symbolizer};
use disasm::{CpuArch, SourceLocation, SourceLookup};
use failure::Error;
use minidump::{Minidump, MinidumpException, MinidumpMemoryList, MinidumpModuleList,
               MinidumpSystemInfo};
use minidump::system_info::CPU;
use reqwest::Client;
use std::env;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use structopt::StructOpt;

#[derive(StructOpt)]
#[structopt(name = "get-minidump-instructions", about = "Display instructions from a minidump")]
struct GetMinidumpInstructions {
    #[structopt(short = "v", long = "verbose", help = "Enable verbose output")]
    #[allow(unused)]
    verbose: bool,
    #[structopt(help = "Input minidump", parse(from_os_str))]
    minidump: PathBuf,
}

struct SymLookup {
    modules: MinidumpModuleList,
    symbolizer: Symbolizer,
    client: Client,
}

struct HgWebFile {
    host: String,
    repo: String,
    rev: String,
    path: String,
}

struct GitHubFile {
    repo: String,
    rev: String,
    path: String,
}

trait VCSFile {
    fn raw_url(&self) -> String;
    fn annotate_url(&self, line: u64) -> String;
    fn as_local_filename(&self) -> String;
}

impl VCSFile for HgWebFile {
    fn raw_url(&self) -> String {
        format!("https://{}/{}/raw-file/{}/{}",
                self.host, self.repo, self.rev, self.path)
    }

    fn annotate_url(&self, line: u64) -> String {
        format!("https://{}/{}/annotate/{}/{}#l{}",
                self.host, self.repo, self.rev, self.path, line)
    }
    fn as_local_filename(&self) -> String {
        format!("{}_{}_{}", self.host, self.rev, self.path).replace('/', "_")
    }
}

impl VCSFile for GitHubFile {
    fn raw_url(&self) -> String {
        format!("http://raw.githubusercontent.com/{}/{}/{}", self.repo, self.rev, self.path)
    }
    fn annotate_url(&self, line: u64) -> String {
        format!("https://github.com/{}/blob/{}/{}#L{}", self.repo, self.rev, self.path, line)
    }
    fn as_local_filename(&self) -> String {
        format!("{}_{}_{}", self.repo, self.rev, self.path).replace('/', "_")
    }
}

fn file_exists(path: &Path) -> bool {
    fs::metadata(path).is_ok()
}

fn fetch_url_to_path(client: &Client, url: &str, path: &Path) -> Result<(), Error> {
    debug!("fetch_url_to_path({}, {:?})", url, path);
    let mut res = client.get(url).send()?.error_for_status()?;
    debug!("fetch_url_to_path: HTTP success");
    let mut tmp_path = path.to_owned().into_os_string();
    tmp_path.push(".tmp");
    {
        let mut f = File::create(&tmp_path)?;
        res.copy_to(&mut f)?;
    }
    fs::rename(&tmp_path, &path)?;
    Ok(())
}

fn parse_vcs_info(filename: &str) -> Result<Box<VCSFile>, Error> {
    let mut bits = filename.split(':');
    Ok(match (bits.next(), bits.next(), bits.next(), bits.next()) {
        (Some("hg"), Some(repo), Some(path), Some(rev)) if repo.starts_with("hg.mozilla.org/") => {
            let mut s = repo.splitn(2, '/');
            let host = s.next().unwrap().to_owned();
            let repo = s.next().unwrap().to_owned();
            let path = path.to_owned();
            let rev = rev.to_owned();
            Box::new(HgWebFile {
                host,
                repo,
                rev,
                path,
            })
        }
        (Some("git"), Some(repo), Some(path), Some(rev)) if repo.starts_with("github.com/") => {
            let repo = repo.splitn(2, '/').nth(1).unwrap().to_owned();
            let path = path.to_owned();
            let rev = rev.to_owned();
            Box::new(GitHubFile {
                repo,
                rev,
                path,
            })
        }
        _ => return Err(format_err!("No VCS info in filename")),
    })
}

fn maybe_fetch_source_file(client: &Client, url: &str, path: &Path) -> Result<(), Error> {
    if file_exists(path) {
        Ok(())
    } else {
        fetch_url_to_path(client, url, path)
    }
}

impl SourceLookup for SymLookup {
    fn lookup(&mut self, address: u64) -> Option<SourceLocation> {
        self.modules.module_at_address(address).and_then(|module| {
            let mut frame = SimpleFrame::with_instruction(address);
            self.symbolizer.fill_symbol(module, &mut frame);
            let SimpleFrame { source_file, source_line, .. } = frame;
            if let (Some(file), Some(line)) = (source_file, source_line) {
                let line = line as u64;
                match parse_vcs_info(&file) {
                    Ok(info) => {
                        let url = info.raw_url();
                        let local = env::temp_dir().join(info.as_local_filename());
                        if maybe_fetch_source_file(&self.client, &url, &local).is_ok() {
                            return Some(SourceLocation {
                                file: local,
                                file_display: Some(info.annotate_url(line)),
                                line
                            })
                        }
                    }
                    _ => {}
                }
                // If fetching the file doesn't work, just hand back the original filename.
                Some(SourceLocation { file: file.into(), file_display: None, line })
            } else {
                // We didn't find any source info.
                None
            }
        })
    }
}

pub fn get_minidump_instructions() -> Result<(), Error> {
    env_logger::init();
    let opt = GetMinidumpInstructions::from_args();
    let mut dump = Minidump::read_path(&opt.minidump)?;
    let modules = dump.get_stream::<MinidumpModuleList>()?;
    let exception = dump.get_stream::<MinidumpException>()?;
    let context = exception.context.as_ref().ok_or(format_err!("Missing exception context"))?;
    let ip = context.get_instruction_pointer();
    let memory_list = dump.get_stream::<MinidumpMemoryList>()?;
    let memory = memory_list.memory_at_address(ip)
        .ok_or(format_err!("Minidump doesn't contain a memory region that contains the instruction pointer from the exception record"))?;
    let sys_info = dump.get_stream::<MinidumpSystemInfo>()?;
    let arch = match sys_info.cpu {
        CPU::X86 => CpuArch::X86,
        CPU::X86_64 => CpuArch::X86_64,
        _ => return Err(format_err!("Unsupported CPU architecture: {}", sys_info.cpu)),
    };
    let supplier = SimpleSymbolSupplier::new(vec!(PathBuf::from("/tmp/symbols")));
    let symbolizer = Symbolizer::new(supplier);
    let client = Client::new();
    let mut lookup = SymLookup { modules, symbolizer, client };
    println!("Faulting instruction pointer: {:#x}", ip);
    info!("Disassembling {} bytes starting at {:#x} of arch {:?}",
          memory.bytes.len(), memory.base_address, arch);
    disasm::disasm_bytes(&memory.bytes,
                         memory.base_address,
                         arch,
                         Some(ip),
                         &mut lookup)?;
    Ok(())
}
