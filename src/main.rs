extern crate clap;
extern crate env_logger;

#[macro_use]
extern crate log;

#[cfg(test)]
extern crate kernel32;

extern crate winapi;


include!(concat!(env!("OUT_DIR"), "/version.rs"));

#[cfg(windows)]
mod acl;
mod appcontainer;
mod winffi;
mod asw;


#[cfg(not(test))]
use asw::HasRawHandle;

#[cfg(test)]
use winapi::{INVALID_HANDLE_VALUE, DWORD, INFINITE, WAIT_OBJECT_0};

#[cfg(test)]
use std::env;

#[allow(unused_imports)]
use winffi::{GENERIC_READ, GENERIC_EXECUTE, GENERIC_ALL};

#[cfg(not(test))]
use std::process;

#[cfg(all(not(test), windows))]
use winapi::HANDLE;

use std::path::{Path, PathBuf};

#[allow(unused_imports)]
use log::*;

#[cfg(not(test))]
use clap::{Arg, App, SubCommand, ArgMatches};

#[cfg(not(test))]
fn build_version() -> String {
    let prebuilt_ver = semver();
    if prebuilt_ver.len() == 0 {
        return format!("build-{} ({})", short_sha(), short_now());
    }

    format!("{}", prebuilt_ver)
}

#[cfg(windows)]
fn add_sid_profile_entry(path: &Path, sid: &str, mask: u32) -> bool {
    // NOTE: Will this mess up for special unicode paths?
    let result = acl::SimpleDacl::from_path(path.to_str().unwrap());
    if let Err(x) = result {
        error!("Failed to get ACL from {:?}: error={:}", path, x);
        return false;
    }

    let mut dacl = result.unwrap();

    if dacl.entry_exists(sid, acl::ACCESS_ALLOWED).is_some() {
        if !dacl.remove_entry(sid, acl::ACCESS_ALLOWED) {
            error!("Failed to remove existing ACL entry for AppContainer SID");
            return false;
        }
    }

    if !dacl.add_entry(acl::AccessControlEntry {
                           entryType: acl::ACCESS_ALLOWED,
                           flags: 0,
                           mask: mask,
                           sid: sid.to_string(),
                       }) {
        error!("Failed to add AppContainer profile ACL entry from {:?}",
               path);
        return false;
    }

    match dacl.apply_to_path(path.to_str().unwrap()) {
        Ok(_) => {
            info!("  Added ACL entry for AppContainer profile in {:?}", path);
        }
        Err(x) => {
            error!("Failed to set new ACL into {:?}: error={:}", path, x);
            return false;
        }
    }

    true
}

#[cfg(all(windows, not(test)))]
#[allow(unreachable_code)]
fn do_run(matches: &ArgMatches) {
    let key_path = PathBuf::from(matches.value_of("key").unwrap());
    info!("  key_path = {:?}", key_path);

    if !key_path.exists() || key_path.is_dir() || !key_path.is_file() {
        error!("Specified key path ({:?}) is invalid", key_path);
        process::exit(-1);
    }

    let child_path = Path::new(matches.value_of("CHILD_PATH").unwrap());
    info!("  child_path = {:?}", child_path);

    if !child_path.exists() || child_path.is_dir() || !child_path.is_file() {
        error!("Specified child path ({:?}) is invalid", child_path);
        process::exit(-1);
    }

    let port = matches.value_of("port").unwrap();
    info!("  tcp server port = {:}", port);

    let profile_name = matches.value_of("name").unwrap();

    // NOTE: Will special unicode paths mess up this unwrap()?
    let mut profile = match appcontainer::Profile::new(profile_name,
                                                       child_path.to_str().unwrap()) {
        Ok(x) => x,
        Err(x) => {
            error!("Failed to create AppContainer profile for {:}: error={:}",
                   profile_name,
                   x);
            process::exit(-1);
        }
    };
    info!("  profile name = {:}", profile_name);
    info!("  sid = {:}", profile.sid);

    profile.enable_outbound_network(matches.is_present("outbound"));
    info!("AppContainer.enable_outbound_network_conn = {:}",
          matches.is_present("outbound"));

    profile.enable_debug(matches.is_present("debug"));
    info!("AppContainer.enable_debug = {:}",
          matches.is_present("debug"));

    let mut key_dir_path = key_path.clone();
    key_dir_path.pop();

    if !add_sid_profile_entry(&key_dir_path, &profile.sid, GENERIC_READ | GENERIC_EXECUTE) {
        error!("Failed to add AppContainer profile ACL entry into {:?}",
               key_dir_path);
        process::exit(-1);
    }

    if !add_sid_profile_entry(&key_path, &profile.sid, GENERIC_READ) {
        error!("Failed to add AppContainer profile ACL entry into {:?}",
               key_path);
        process::exit(-1);
    }

    {
        let key_dir_abspath = key_dir_path.canonicalize().unwrap();
        info!("key_dir_abspath = {:?}", key_dir_abspath);

        info!("Attempting to bind to port {:}", port);
        let server = match asw::TcpServer::bind(port) {
            Ok(x) => x,
            Err(x) => {
                error!("Failed to bind server socket on port {:}: GLE={:}", port, x);
                process::exit(-1);
            }
        };

        println!("Listening for clients on port {:}", port);

        loop {
            match server.get_event() {
                asw::TcpServerEvent::Accept => {
                    let raw_client = server.accept();
                    if raw_client.is_some() {
                        let (client, addr) = raw_client.unwrap();
                        let raw_socket = client.raw_handle();

                        match profile.launch(raw_socket as HANDLE,
                                             raw_socket as HANDLE,
                                             key_dir_abspath.to_str().unwrap()) {
                            Ok(x) => {
                                info!("     Launched new process with handle {:?} with current_dir = {:?}",
                                      x.raw,
                                      key_dir_path);
                                println!(" + Accepted new client connection from {:}", addr);
                            }
                            Err(x) => {
                                error!("     Failed to launch new process: error={:}", x);
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        process::exit(0);
    }
}

#[cfg(windows)]
fn remove_sid_acl_entry(path: &Path, sid: &str) -> bool {
    // NOTE: Will this mess up for special unicode paths?
    let result = acl::SimpleDacl::from_path(path.to_str().unwrap());
    if let Err(x) = result {
        error!("Failed to get ACL from {:?}: error={:}", path, x);
        return false;
    }

    let mut dacl = result.unwrap();

    if !dacl.remove_entry(sid, acl::ACCESS_ALLOWED) {
        error!("Failed to remove AppContainer profile ACL entry from {:?}",
               path);
        return false;
    }

    match dacl.apply_to_path(path.to_str().unwrap()) {
        Ok(_) => {
            info!("  Removed ACL entry for AppContainer profile in {:?}", path);
        }
        Err(x) => {
            error!("Failed to set new ACL into {:?}: error={:}", path, x);
            return false;
        }
    }

    true
}

#[cfg(all(windows, not(test)))]
fn do_clean(matches: &ArgMatches) {
    let profile_name = matches.value_of("name").unwrap();
    println!("Removing AppContainer profile \"{:}\"", profile_name);

    if let Some(raw_key_path) = matches.value_of("key") {
        let key_path = PathBuf::from(raw_key_path);
        let mut key_dir_path = key_path.clone();
        key_dir_path.pop();

        info!("  key_path = {:?}", key_path);
        info!("  key_dir_path = {:?}", key_dir_path);

        if !key_path.exists() || key_path.is_dir() || !key_path.is_file() {
            error!("Specified key path ({:?}) is invalid", key_path);
            process::exit(-1);
        }

        // We create the profile_name with key_path as the child process in order
        // to get the AppContainer SID for profile_name
        let profile = match appcontainer::Profile::new(profile_name, key_path.to_str().unwrap()) {
            Ok(x) => x,
            Err(x) => {
                error!("Failed to get profile information for \"{:}\": error={:}",
                       profile_name,
                       x);
                process::exit(-1);
            }
        };

        info!("Removing ACL entry for {:} in {:?}", profile.sid, key_path);
        if !remove_sid_acl_entry(&key_path, &profile.sid) {
            error!("Failed to remove entry for key_path={:?}", key_path);
        }

        info!("Removing ACL entry for {:} in {:?}",
              profile.sid,
              key_dir_path);
        if !remove_sid_acl_entry(&key_dir_path, &profile.sid) {
            error!("Failed to remove entry for key_dir_path={:?}", key_dir_path);
        }
    }

    if !appcontainer::Profile::remove(profile_name) {
        error!("  Failed to remove \"{:}\" profile", profile_name);
    } else {
        println!("  SUCCESS - removed \"{:}\" profile", profile_name);
    }

    process::exit(0);
}

#[cfg(all(windows, not(test)))]
fn main() {
    let app_version: &str = &build_version();
    let matches = App::new("AppJailLauncher")
        .version(app_version)
        .author("author <email>")
        .about("A TCP server meant for spawning AppContainer'd client processes for Windows-based CTF challenges")
        .subcommand(SubCommand::with_name("run")
            .version(app_version)
            .about("Launch a TCP server")
            .arg(Arg::with_name("name")
                     .short("n")
                     .long("name")
                     .value_name("NAME")
                     .default_value("default_appjail_profile")
                     .help("AppContainer profile name"))
            .arg(Arg::with_name("debug")
                     .long("debug")
                     .help("Enable debug mode where the AppContainers are disabled"))
            .arg(Arg::with_name("outbound")
                     .long("enable-outbound")
                     .help("Enables outbound network connections from the AppContainer'd process"))
            .arg(Arg::with_name("key")
                     .short("k")
                     .long("key")
                     .value_name("KEYFILE")
                     .required(true)
                     .help("The path to the \"key\" file that contains the challenge solution token"))
            .arg(Arg::with_name("port")
                     .short("p")
                     .long("port")
                     .value_name("PORT")
                     .default_value("4444")
                     .help("Port to bind the TCP server on"))
            .arg(Arg::with_name("CHILD_PATH")
                     .index(1)
                     .required(true)
                     .help("Path to the child process to be AppContainer'd upon TCP client acceptance")))
        .subcommand(SubCommand::with_name("clean")
            .version(app_version)
            .about("Clean AppContainer profiles that have been created on the system")
            .arg(Arg::with_name("name")
                     .short("n")
                     .long("name")
                     .value_name("NAME")
                     .default_value("default_appjail_profile")
                     .help("AppContainer profile name"))
            .arg(Arg::with_name("key")
                     .short("k")
                     .long("key")
                     .value_name("KEYFILE")
                     .help("The path to the \"key\" file that contains the challenge solution token")))
        .get_matches();

    if let Err(_) = env_logger::init() {
        println!("FATAL: failed to initialize env_logger!");
        process::exit(-1);
    }

    if let Some(run_matches) = matches.subcommand_matches("run") {
        info!("Detected subcommand 'run'");
        do_run(run_matches);
    } else if let Some(clean_matches) = matches.subcommand_matches("clean") {
        info!("Detected subcommand 'clean");
        do_clean(clean_matches);
    } else {
        error!("No subcommand provided!");
        process::exit(1);
    }
}

#[cfg(not(windows))]
fn main() {
    println!("Build target is not supported!");
    process::exit(-1);
}

// ----- UNIT TESTS -----
#[cfg(test)]
const KEY_READ_MASK: u32 = 0x00000020;

#[cfg(test)]
fn get_unittest_support_path() -> Option<PathBuf> {
    let mut dir_path = match env::current_exe() {
        Ok(x) => x,
        Err(_) => return None,
    };

    while dir_path.pop() {
        dir_path.push("unittest_support");
        if dir_path.exists() && dir_path.is_dir() {
            return Some(dir_path);
        }
        dir_path.pop();
    }

    None
}

#[cfg(test)]
struct ProfileWrapper {
    name: String,
}

#[cfg(test)]
impl Drop for ProfileWrapper {
    fn drop(&mut self) {
        appcontainer::Profile::remove(&self.name);
    }
}

#[cfg(test)]
struct AclOp {
    path: PathBuf,
    sid: String,
}

#[cfg(test)]
impl AclOp {
    fn add(path: &PathBuf, sid: &str, mask: u32) -> Option<AclOp> {
        if !add_sid_profile_entry(&path, sid, mask) {
            return None;
        }

        Some(AclOp {
                 path: PathBuf::from(path),
                 sid: sid.to_string(),
             })
    }
}

#[cfg(test)]
impl Drop for AclOp {
    fn drop(&mut self) {
        remove_sid_acl_entry(&self.path, &self.sid);
    }
}

#[allow(unused_variables)]
#[allow(non_snake_case)]
#[test]
fn test_sandbox_key_read() {
    let result = get_unittest_support_path();
    assert!(!result.is_none());

    let profile_name = String::from("test_default_appjail1");

    let mut child_path = result.unwrap();
    let mut dir_path = child_path.clone();
    child_path.push("sandbox-test.exe");

    dir_path.push("pub");

    let mut key_path = dir_path.clone();
    key_path.push("pub");
    key_path.push("key2.txt");

    println!("dir_path = {:?}", dir_path);
    println!("key_path = {:?}", key_path);
    println!("Attempting to create AppContainer profile...");

    if let Ok(profile) = appcontainer::Profile::new(&profile_name, child_path.to_str().unwrap()) {
        let wrapper = ProfileWrapper { name: profile_name };

        println!("Setting ACLs for {:} on {:?}", &profile.sid, dir_path);
        let dirAclOp = AclOp::add(&dir_path, &profile.sid, GENERIC_READ | GENERIC_EXECUTE);
        assert!(dirAclOp.is_some());

        println!("Setting ACLs for {:} on {:?}", &profile.sid, key_path);
        let fileAclOp = AclOp::add(&key_path, &profile.sid, GENERIC_READ);
        assert!(fileAclOp.is_some());

        println!("Testing with default privileges");
        let launch_result = profile.launch(INVALID_HANDLE_VALUE,
                                           INVALID_HANDLE_VALUE,
                                           dir_path.to_str().unwrap());
        assert!(launch_result.is_ok());

        let hProcess = launch_result.unwrap();
        assert_eq!(unsafe { kernel32::WaitForSingleObject(hProcess.raw, INFINITE) },
                   WAIT_OBJECT_0);

        let mut dwExitCode: DWORD = 0 as DWORD;
        assert!(unsafe { kernel32::GetExitCodeProcess(hProcess.raw, &mut dwExitCode) } != 0);
        println!("ExitCode = {:08x}", dwExitCode);

        assert!((dwExitCode & KEY_READ_MASK) == 0)
    } else {
        println!("Failed to create AppContainer profile");
        assert!(false);
    }
}
