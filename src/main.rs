use instant_rpc::{OldFaithfulClient, OldFaithfulConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = OldFaithfulConfig::default();
    let client = OldFaithfulClient::new(config)?;
    println!(
        "instant-rpc transport ready (base_url={}, max_slice_bytes={}, max_concurrent_requests={})",
        client.base_url(),
        client.config().max_slice_bytes,
        client.config().max_concurrent_requests,
    );
    Ok(())
}
