//! WASM bindings for netaddr functionality

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

#[cfg(feature = "wasm")]
use crate::ip::{IPAddress, IPNetwork};
#[cfg(feature = "wasm")]
use crate::eui::EUI;
#[cfg(feature = "wasm")]
use crate::sets::IPSet;
#[cfg(feature = "wasm")]
use std::str::FromStr;

#[cfg(feature = "wasm")]
#[wasm_bindgen(start)]
pub fn main() {
    console_error_panic_hook::set_once();
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub struct NetaddrAPI;

#[cfg(feature = "wasm")]
#[wasm_bindgen]
impl NetaddrAPI {
    #[wasm_bindgen(constructor)]
    pub fn new() -> NetaddrAPI {
        NetaddrAPI
    }

    #[wasm_bindgen(js_name = parseIP)]
    pub fn parse_ip(&self, addr_str: &str) -> Result<String, JsValue> {
        IPAddress::from_str(addr_str)
            .map(|addr| format!("{}", addr))
            .map_err(|e| JsValue::from_str(&format!("Error: {}", e)))
    }

    #[wasm_bindgen(js_name = getIPInfo)]
    pub fn get_ip_info(&self, addr_str: &str) -> Result<String, JsValue> {
        let addr = IPAddress::from_str(addr_str)
            .map_err(|e| JsValue::from_str(&format!("Error: {}", e)))?;

        let info = serde_json::json!({
            "address": addr.to_string(),
            "version": addr.version(),
            "is_private": addr.is_private(),
            "is_loopback": addr.is_loopback(),
            "is_multicast": addr.is_multicast(),
            "is_link_local": addr.is_link_local(),
            "is_unspecified": addr.is_unspecified(),
            "hex": addr.to_hex(),
            "binary": addr.to_binary(),
            "reverse_dns": addr.reverse_dns()
        });

        Ok(info.to_string())
    }

    #[wasm_bindgen(js_name = parseNetwork)]
    pub fn parse_network(&self, network_str: &str) -> Result<String, JsValue> {
        IPNetwork::from_str(network_str)
            .map(|net| {
                serde_json::json!({
                    "network": net.to_string(),
                    "network_address": net.network_address().to_string(),
                    "broadcast_address": match net.broadcast_address() {
                        Ok(addr) => addr.to_string(),
                        Err(_) => "N/A".to_string()
                    },
                    "prefix_len": net.prefix_length(),
                    "netmask": match net.netmask() {
                        Ok(addr) => addr.to_string(),
                        Err(_) => "N/A".to_string()
                    },
                    "hostmask": "N/A",
                    "num_hosts": net.hosts().count(),
                    "is_subnet_of": "call with another network",
                    "subnets": format!("{} subnets available", net.hosts().count())
                }).to_string()
            })
            .map_err(|e| JsValue::from_str(&format!("Error: {}", e)))
    }

    #[wasm_bindgen(js_name = parseMAC)]
    pub fn parse_mac(&self, mac_str: &str) -> Result<String, JsValue> {
        EUI::from_str(mac_str)
            .map(|eui| {
                serde_json::json!({
                    "address": eui.to_string(),
                    "type": if eui.is_mac48() { "EUI-48 (MAC)" } else { "EUI-64" },
                    "oui": hex::encode(eui.oui()),
                    "is_unicast": eui.is_unicast(),
                    "is_multicast": eui.is_multicast(),
                    "is_universal": eui.is_universal(),
                    "is_local": eui.is_local(),
                    "bytes": eui.bytes(),
                    "length": eui.len()
                }).to_string()
            })
            .map_err(|e| JsValue::from_str(&format!("Error: {}", e)))
    }

    #[wasm_bindgen(js_name = createIPSet)]
    pub fn create_ip_set(&self, addresses: &str) -> Result<String, JsValue> {
        let addr_list: Vec<&str> = addresses.split(',').collect();
        let mut ip_set = IPSet::new();

        let mut count = 0;
        for addr_str in addr_list {
            let addr_str = addr_str.trim();
            if let Ok(addr) = IPAddress::from_str(addr_str) {
                if ip_set.add_address(addr).is_ok() {
                    count += 1;
                }
            } else if let Ok(net) = IPNetwork::from_str(addr_str) {
                if ip_set.add_network(net).is_ok() {
                    count += 1;
                }
            }
        }

        Ok(format!("IP Set with {} entries processed", count))
    }

    #[wasm_bindgen(js_name = getNextIP)]
    pub fn get_next_ip(&self, addr_str: &str) -> Result<String, JsValue> {
        let addr = IPAddress::from_str(addr_str)
            .map_err(|e| JsValue::from_str(&format!("Error: {}", e)))?;

        addr.next()
            .map(|next| next.to_string())
            .ok_or_else(|| JsValue::from_str("No next address available"))
    }

    #[wasm_bindgen(js_name = getPrevIP)]
    pub fn get_prev_ip(&self, addr_str: &str) -> Result<String, JsValue> {
        let addr = IPAddress::from_str(addr_str)
            .map_err(|e| JsValue::from_str(&format!("Error: {}", e)))?;

        addr.prev()
            .map(|prev| prev.to_string())
            .ok_or_else(|| JsValue::from_str("No previous address available"))
    }

    #[wasm_bindgen(js_name = subnetNetwork)]
    pub fn subnet_network(&self, network_str: &str, new_prefix: u8) -> Result<String, JsValue> {
        let network = IPNetwork::from_str(network_str)
            .map_err(|e| JsValue::from_str(&format!("Error: {}", e)))?;

        let subnets = network.subnets(new_prefix)
            .map_err(|e| JsValue::from_str(&format!("Error: {}", e)))?;

        let subnet_list: Vec<String> = subnets.into_iter()
            .take(20) // Limit to first 20 subnets
            .map(|subnet| subnet.to_string())
            .collect();

        Ok(serde_json::json!({
            "original": network.to_string(),
            "new_prefix": new_prefix,
            "subnets": subnet_list
        }).to_string())
    }
}

#[cfg(feature = "wasm")]
impl Default for NetaddrAPI {
    fn default() -> Self {
        Self::new()
    }
}