#![cfg(windows)]

extern crate clap;
extern crate env_logger;
extern crate field_offset;
extern crate libc;

#[macro_use]
extern crate log;
extern crate widestring;
extern crate winapi;
extern crate windows_acl;

include!(concat!(env!("OUT_DIR"), "/version.rs"));

mod appcontainer;
mod asw;
mod utils;

#[cfg(test)]
mod tests;

use asw::HasRawHandle;

use winapi::um::winnt::{GENERIC_EXECUTE, GENERIC_READ, HANDLE, PSID};
use windows_acl::acl::{ACL, AceType};
use windows_acl::helper::{string_to_sid};

use std::path::{Path, PathBuf};
use std::process;

#[allow(unused_imports)]
use log::*;

use clap::{Arg, App, SubCommand, ArgMatches};

fn build_version() -> String {
    let prebuilt_ver = semver();
    if prebuilt_ver.len() == 0 {
        return format!("build-{} ({})", short_sha(), short_now());
    }

    format!("{}", prebuilt_ver)
}

pub fn add_sid_profile_entry(path: &Path, string_sid: &str, mask: u32) -> bool {
    let string_path = path.to_str().unwrap_or("");
    if string_path.is_empty() {
        error!("Path contains invalid characters: path={:?}", path);
        return false;
    }

    match ACL::from_file_path(string_path, false) {
        Ok(mut acl) => {
            let sid = string_to_sid(string_sid).unwrap_or(Vec::new());
            if sid.capacity() == 0 {
                error!("Failed to convert string SID to SID: sid={:?}", string_sid);
                return false;
            }

            acl.remove(sid.as_ptr() as PSID, Some(AceType::AccessAllow), None).unwrap_or_else(|code| { 
                error!("Failed to remove existing entry for sid={:?}: error={}", string_sid, code);
                0
            });

            if !acl.allow(sid.as_ptr() as PSID, true, mask).unwrap_or_else(|code| {
                   error!("Failed to add access allowed entry: error={}", code);
                   false
               }) {
                return false;
            }

        },
        Err(code) => {
            error!("Failed to get ACL from {:?} while adding ACL entry: error={}", path, code);
            return false;
        }
    }

    true
}

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

pub fn remove_sid_acl_entry(path: &Path, string_sid: &str) -> bool {
    let string_path = path.to_str().unwrap_or("");
    if string_path.is_empty() {
        error!("Path contains invalid characters: path={:?}", path);
        return false;
    }

    match ACL::from_file_path(string_path, false) {
        Ok(mut acl) => {
            let sid = string_to_sid(string_sid).unwrap_or(Vec::new());
            if sid.capacity() == 0 {
                error!("Failed to convert string SID into SID: sid={:?}", string_sid);
                return false;
            }

            let result = acl.remove(sid.as_ptr() as PSID, Some(AceType::AccessAllow), None);
            if result.is_err() {
                error!("Failed to remove ACL for sid={:?}: error={}", string_sid, result.unwrap_err());
                return false;
            }
        },
        Err(code) => {
            error!("Failed to get ACL from path while removing ACL entry: path={:?}, error={}", path, code);
            return false;
        }
    }

    true
}

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

fn main() {
    let app_version: &str = &build_version();
    let matches = App::new("AppJailLauncher")
        .version(app_version)
        .author("Andy Ying <andy@trailofbits.com>")
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