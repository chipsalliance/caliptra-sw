// Licensed under the Apache-2.0 license

use std::fmt::{Debug, Display};
use std::str::FromStr;

use anyhow::{anyhow, Context};

/// Identifies a USB device connected to a particular port (For example "3-1.4")
#[derive(Clone, Eq, PartialEq)]
pub struct UsbPortPath {
    pub bus: u8,
    pub ports: Vec<u8>,
}
impl UsbPortPath {
    #[allow(unused)]
    pub fn new(bus: u8, ports: Vec<u8>) -> Self {
        Self { bus, ports }
    }
    pub fn child(&self, index: u8) -> Self {
        let mut ports = self.ports.clone();
        ports.push(index);
        Self {
            bus: self.bus,
            ports,
        }
    }
}

impl FromStr for UsbPortPath {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let context = || format!("Unable to parse UsbPortPath {s:?}");
        let Some((root, remainder)) = s.split_once('-') else {
            return Err(anyhow!("no '-'")).with_context(context);
        };
        let bus = u8::from_str(root).with_context(context)?;
        let mut ports = vec![];
        for item in remainder.split('.') {
            ports.push(u8::from_str(item).with_context(context)?);
        }
        Ok(UsbPortPath { bus, ports })
    }
}

impl Display for UsbPortPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.bus)?;
        for (index, item) in self.ports.iter().enumerate() {
            if index == 0 {
                write!(f, "-")?;
            } else {
                write!(f, ".")?;
            }
            write!(f, "{}", item)?;
        }
        Ok(())
    }
}
impl Debug for UsbPortPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_path_parse() {
        assert_eq!(
            UsbPortPath::from_str("5-1.2.3.23").unwrap(),
            UsbPortPath::new(5, vec![1, 2, 3, 23])
        );
        assert_eq!(
            UsbPortPath::from_str("23-6").unwrap(),
            UsbPortPath::new(23, vec![6])
        );
        assert_eq!(
            UsbPortPath::from_str("23-a").unwrap_err().to_string(),
            "Unable to parse UsbPortPath \"23-a\""
        );
        assert_eq!(
            UsbPortPath::from_str("23").unwrap_err().to_string(),
            "Unable to parse UsbPortPath \"23\""
        );
        assert_eq!(
            UsbPortPath::from_str("").unwrap_err().to_string(),
            "Unable to parse UsbPortPath \"\""
        );
    }

    #[test]
    fn test_port_path_display() {
        assert_eq!(UsbPortPath::new(52, vec![1, 4]).to_string(), "52-1.4");
    }
}
