#[path = "../firewall.rs"]
mod firewall;
fn main() {
    if let Err(e) = firewall::helper() {
        println!("{}", serde_json::json!({"error":e}));
        std::process::exit(1);
    }
}
#[path = "../networks.rs"]
mod networks;
