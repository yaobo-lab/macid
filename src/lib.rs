//! Get an encrypted unique MachineID/HWID/UUID.
//!
//! This crate is inspired by .Net DeviceId
//!
//! You can add all the components you need without admin permissions.
//!
//! ```
//! use machineid_rs::{IdBuilder, Encryption, HWIDComponent};
//!
//! // There are 3 different encryption types: MD5, SHA1 and SHA256.
//! let mut builder = IdBuilder::new();
//!
//! builder.add_component(HWIDComponent::SystemID).add_component(HWIDComponent::CPUCores);
//!
//! let hwid = builder.build("mykey").unwrap();

#![allow(non_snake_case)]

mod errors;
mod linux;
mod macos;
mod utils;
mod windows;

use errors::HWIDError;
#[cfg(target_os = "linux")]
use linux::{get_disk_id, get_hwid, get_mac_address};
#[cfg(target_os = "macos")]
use macos::{get_disk_id, get_hwid, get_mac_address};

#[cfg(target_os = "windows")]
use windows::{get_disk_id, get_hwid, get_mac_address};

use hmac::{Hmac, Mac};
use md5::Md5;
use sysinfo::System;
use utils::file_token;

#[derive(PartialEq, Eq, Hash)]
pub enum HWIDComponent {
    /// System UUID
    SystemID,
    /// Number of CPU Cores
    CPUCores,
    /// Name of the OS
    OSName,
    /// Current Username
    Username,
    /// Host machine name
    MachineName,
    /// Mac Address
    MacAddress,
    /// CPU Vendor ID
    CPUID,
    /// The contents of a file
    FileToken(&'static str),
    /// UUID of the root disk
    DriveSerial,
}

impl HWIDComponent {
    fn name(&self) -> &str {
        match self {
            HWIDComponent::SystemID => "SystemID",
            HWIDComponent::CPUCores => "CPUCores",
            HWIDComponent::OSName => "OSName",
            HWIDComponent::Username => "Username",
            HWIDComponent::MachineName => "MachineName",
            HWIDComponent::MacAddress => "MacAddress",
            HWIDComponent::CPUID => "CPUID",
            HWIDComponent::FileToken(_) => "SystemID",
            HWIDComponent::DriveSerial => "DriveSerial",
        }
    }

    fn to_string(&self) -> Result<String, HWIDError> {
        use HWIDComponent::*;
        match self {
            SystemID => get_hwid(),
            CPUCores => {
                let sys = System::new_all();
                let cores = sys.cpus().len();
                Ok(cores.to_string())
            }
            OSName => {
                let name = System::long_os_version()
                    .ok_or(HWIDError::new("OSName", "Could not retrieve OS Name"))?;

                Ok(name)
            }
            Username => Ok(whoami::username()),
            MachineName => {
                let name = System::host_name()
                    .ok_or(HWIDError::new("HostName", "Could not retrieve Host Name"))?;

                Ok(name)
            }
            MacAddress => get_mac_address(),
            CPUID => {
                let sys = System::new_all();
                let mut cupid = String::from("");
                for cpu in sys.cpus() {
                    cupid = format!("{}-{}", cupid, cpu.vendor_id());
                }
                Ok(cupid)
            }
            FileToken(filename) => {
                let id = file_token(filename)?;
                Ok(id)
            }
            DriveSerial => get_disk_id(),
        }
    }
}

/// The encryptions that can be used to build the HWID.
pub enum Encryption {
    MD5,
    MD516,
    MD520,
}

type HmacMd5 = Hmac<Md5>;
// type HmacSha1 = Hmac<Sha1>;
// type HmacSha256 = Hmac<Sha256>;

impl Encryption {
    fn generate_hash(&self, key: &[u8], text: String) -> Result<String, HWIDError> {
        match self {
            Encryption::MD5 => {
                let mut mac = HmacMd5::new_from_slice(key)?;
                mac.update(text.as_bytes());
                let result = mac.finalize();
                Ok(hex::encode(result.into_bytes().as_slice()))
            }
            Encryption::MD520 => {
                let mut mac = HmacMd5::new_from_slice(key)?;
                mac.update(text.as_bytes());
                let result = mac.finalize();
                Ok(hex::encode(result.into_bytes().as_slice())[0..20].to_string())
            }
            Encryption::MD516 => {
                let mut mac = HmacMd5::new_from_slice(key)?;
                mac.update(text.as_bytes());
                let result = mac.finalize();
                Ok(hex::encode(result.into_bytes().as_slice())[0..16].to_string())
            } // Encryption::SHA1 => {
              //     let mut mac = HmacSha1::new_from_slice(key)?;
              //     mac.update(text.as_bytes());
              //     let result = mac.finalize();
              //     Ok(hex::encode(result.into_bytes().as_slice()))
              // }
              // Encryption::SHA256 => {
              //     let mut mac = HmacSha256::new_from_slice(key)?;
              //     mac.update(text.as_bytes());
              //     let result = mac.finalize();
              //     Ok(hex::encode(result.into_bytes().as_slice()))
              // }
        }
    }
}

/// `IdBuilder` is the constructor for the HWID. It can be used with the 3 different options of the `Encryption` enum.
pub struct IdBuilder {
    parts: Vec<HWIDComponent>,
}

impl Default for IdBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl IdBuilder {
    /// Joins every part together and returns a `Result` that may be the hashed HWID or a `HWIDError`.
    ///
    /// # Errors
    ///
    /// Returns [`Err`] if there is an error while retrieving the component's strings.
    ///
    /// # Examples
    ///
    /// ```
    /// use machineid_rs::{IdBuilder, Encryption, HWIDComponent};
    ///
    /// let mut builder = IdBuilder::new();
    ///
    /// builder.add_component(HWIDComponent::SystemID);
    ///
    ///
    /// // Will panic if there is an error when the components return his values.
    /// let key = builder.build("mykey").unwrap();
    /// ```
    pub fn encode(&self, key: &str, hash: Encryption) -> Result<String, HWIDError> {
        let id = self.get_id()?;
        hash.generate_hash(key.as_bytes(), id)
    }

    pub fn encode_id(&self, id: String, key: &str, hash: Encryption) -> Result<String, HWIDError> {
        hash.generate_hash(key.as_bytes(), id)
    }
    //打印所有id 值
    pub fn print_all(&self) {
        log::info!(
            "[machineid] SystemID: {}",
            HWIDComponent::SystemID.to_string().unwrap_or_default()
        );
        log::info!(
            "[machineid] OSName: {}",
            HWIDComponent::OSName.to_string().unwrap_or_default()
        );
        log::info!(
            "[machineid] CPUCores: {}",
            HWIDComponent::CPUCores.to_string().unwrap_or_default()
        );
        log::info!(
            "[machineid] Username: {}",
            HWIDComponent::Username.to_string().unwrap_or_default()
        );
        log::info!(
            "[machineid] MachineName: {}",
            HWIDComponent::MachineName.to_string().unwrap_or_default()
        );
        log::info!(
            "[machineid] MacAddress: {}",
            HWIDComponent::MacAddress.to_string().unwrap_or_default()
        );
        log::info!(
            "[machineid] CPUID: {}",
            HWIDComponent::CPUID.to_string().unwrap_or_default()
        );
        log::info!(
            "[machineid] DriveSerial: {}",
            HWIDComponent::DriveSerial.to_string().unwrap_or_default()
        );
    }

    //打印所有id 值
    pub fn print_self(&self) {
        for part in self.parts.iter() {
            let id = part.to_string().unwrap_or_else(|e| format!("Err: {}", e));
            log::info!("[machineid] {}: {}", part.name(), id);
        }
    }

    pub fn get_id(&self) -> Result<String, HWIDError> {
        if self.parts.is_empty() {
            HWIDError::new(
                "err",
                "You must add at least one element to make a machine id",
            );
        }
        let id = self
            .parts
            .iter()
            .map(|p| p.to_string())
            .collect::<Result<String, HWIDError>>()?;
        Ok(id)
    }
    /// Adds a component to the `IdBuilder` that will be hashed once you call the [`IdBuilder::build`] function.
    ///
    /// You can't add the same component twice.
    ///
    /// # Examples
    ///
    /// ```
    /// use machineid_rs::{IdBuilder, Encryption, HWIDComponent};
    ///
    /// let mut builder = IdBuilder::new();
    ///
    /// builder.add_component(HWIDComponent::SystemID);
    /// ```
    pub fn add_component(&mut self, component: HWIDComponent) -> &mut Self {
        if !self.parts.contains(&component) {
            self.parts.push(component);
        }
        self
    }

    /// Adds all possible components to the `IdBuilder`.
    ///
    /// # Examples
    ///
    /// ```
    /// use machineid_rs::{IdBuilder, Encryption};
    ///
    /// let mut builder = IdBuilder::new();
    ///
    /// builder.add_all();
    /// ```
    ///
    /// It's the same as doing:
    ///
    /// ```
    /// use machineid_rs::{IdBuilder, Encryption, HWIDComponent};
    ///
    /// let mut builder = IdBuilder::new();
    ///
    /// builder
    ///     .add_component(HWIDComponent::SystemID)
    ///     .add_component(HWIDComponent::OSName)
    ///     .add_component(HWIDComponent::CPUCores)
    ///     .add_component(HWIDComponent::CPUID)
    ///     .add_component(HWIDComponent::DriveSerial)
    ///     .add_component(HWIDComponent::MacAddress)
    ///     .add_component(HWIDComponent::Username)
    ///     .add_component(HWIDComponent::MachineName);
    ///
    /// ```
    pub fn add_all(&mut self) -> &mut Self {
        self.add_component(HWIDComponent::SystemID)
            .add_component(HWIDComponent::OSName)
            .add_component(HWIDComponent::CPUCores)
            .add_component(HWIDComponent::CPUID)
            .add_component(HWIDComponent::DriveSerial)
            .add_component(HWIDComponent::MacAddress)
            .add_component(HWIDComponent::Username)
            .add_component(HWIDComponent::MachineName)
    }

    /// Makes a new IdBuilder with the selected Encryption
    ///
    /// # Examples
    ///
    /// ```
    /// use machineid_rs::{IdBuilder, Encryption};
    ///
    /// let mut builder = IdBuilder::new();
    /// ```
    pub fn new() -> Self {
        IdBuilder { parts: vec![] }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::env;
    use std::process;
    use toolkit_rs::logger::{self, LogConfig};
    #[allow(dead_code)]
    fn init_log() {
        logger::setup(LogConfig::default()).unwrap_or_else(|e| {
            println!("log setup err:{}", e);
            process::exit(1);
        });
    }

    #[test]
    fn every_option_sha256() {
        let mut builder = IdBuilder::new();
        builder
            .add_component(HWIDComponent::SystemID)
            .add_component(HWIDComponent::OSName)
            .add_component(HWIDComponent::CPUCores)
            .add_component(HWIDComponent::CPUID)
            .add_component(HWIDComponent::DriveSerial)
            .add_component(HWIDComponent::MacAddress)
            .add_component(HWIDComponent::FileToken("test.txt"))
            .add_component(HWIDComponent::Username)
            .add_component(HWIDComponent::MachineName);
        let id = builder.get_id().unwrap();
        let hash = builder.encode_id(id, "mykey", Encryption::MD5).unwrap();
        let expected = env::var("SHA256_MACHINEID_HASH").unwrap();
        assert_eq!(expected, hash);
    }

    #[test]
    fn every_option_sha1() {
        let mut builder = IdBuilder::new();
        builder
            .add_component(HWIDComponent::SystemID)
            .add_component(HWIDComponent::OSName)
            .add_component(HWIDComponent::CPUCores)
            .add_component(HWIDComponent::CPUID)
            .add_component(HWIDComponent::DriveSerial)
            .add_component(HWIDComponent::MacAddress)
            .add_component(HWIDComponent::FileToken("test.txt"))
            .add_component(HWIDComponent::Username)
            .add_component(HWIDComponent::MachineName);
        let hash = builder.encode("mykey", Encryption::MD5).unwrap();
        let expected = env::var("SHA1_MACHINEID_HASH").unwrap();
        assert_eq!(expected, hash);
    }

    #[test]
    fn every_option_md5() {
        let mut builder = IdBuilder::new();
        builder
            .add_component(HWIDComponent::SystemID)
            .add_component(HWIDComponent::OSName)
            .add_component(HWIDComponent::CPUCores)
            .add_component(HWIDComponent::CPUID)
            .add_component(HWIDComponent::DriveSerial)
            .add_component(HWIDComponent::MacAddress)
            .add_component(HWIDComponent::FileToken("test.txt"))
            .add_component(HWIDComponent::Username)
            .add_component(HWIDComponent::MachineName);
        let hash = builder.encode("mykey", Encryption::MD5).unwrap();
        let expected = env::var("MD5_MACHINEID_HASH").unwrap();
        assert_eq!(expected, hash);
    }

    #[test]
    fn every_option_md52() {
        let mut builder = IdBuilder::new();
        builder.add_component(HWIDComponent::DriveSerial);
        let id = builder.get_id().unwrap();

        let hash = builder.encode_id(id, "mykey", Encryption::MD5).unwrap();
        let expected = env::var("MD5_MACHINEID_HASH").unwrap();
        assert_eq!(expected, hash);
    }
    //639ad566dd7b7da6
    #[test]
    fn every_option_md516() {
        let mut builder = IdBuilder::new();
        builder.add_component(HWIDComponent::DriveSerial);
        builder.add_component(HWIDComponent::MacAddress);
        let id = builder.get_id().unwrap();

        let hash = builder.encode_id(id, "mykey", Encryption::MD520).unwrap();

        println!("{}", hash);
    }

    #[test]
    fn every_id_test() {
        let builder = IdBuilder::new();
        builder.print_all();
    }
}
