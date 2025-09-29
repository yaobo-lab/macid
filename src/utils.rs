#![allow(dead_code)]
use crate::errors::HWIDError;
use anyhow::Error;
use md5::{Digest, Md5};
use netdev::{get_interfaces, Interface};
use std::fs::OpenOptions;
use std::io::{Read, Write};
use uuid::Uuid;

pub fn get_md5(txt: String) -> String {
    let data = txt.as_bytes();
    let mut hasher = Md5::new();
    hasher.update(data);
    let result = hasher.finalize();
    format!("{:x}", result)
}

pub(crate) fn file_token(path: &str) -> Result<String, HWIDError> {
    let mut file = OpenOptions::new()
        .write(true)
        .read(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    let mut content = String::new();
    file.read_to_string(&mut content)?;
    if content.is_empty() {
        let uuid = Uuid::new_v4().to_string();
        file.write_all(uuid.as_bytes()).unwrap();
        content = uuid.to_string();
    }
    Ok(content)
}

fn get_ifaces() -> Vec<Interface> {
    let ifaces = get_interfaces();
    let mut list = vec![];
    for s in ifaces {
        if s.name.is_empty()
            || s.name.eq("p2p0")
            || s.name.eq("docker0")
            || s.is_loopback()
            || !s.is_physical()
        {
            continue;
        }
        list.push(s);
    }

    list.sort_by_key(|p| p.name.clone());
    return list;
}

pub(crate) fn get_mac_addr() -> Result<String, Error> {
    let ifaces = get_ifaces();
    let mut macs = vec![];
    for s in ifaces.iter() {
        if let Some(mac) = s.mac_addr {
            macs.push(mac.to_string());
        }
    }
    if macs.is_empty() {
        return Err(anyhow::Error::msg("No valid MAC address found"));
    }
    Ok(macs.join("|"))
}

#[test]
fn test_md5() {
    let str = "hello 12121212world dad ik223j2j22jj22222222222222222222sdasdfsdf".to_string();
    println!("{}", get_md5(str));
}
