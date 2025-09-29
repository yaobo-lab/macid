## base on

https://github.com/Taptiive/machineid-rs

## Install

```bash
cargo add macid
```

## Usage

```rust
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
```
