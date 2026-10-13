use jend_model_store::{
    BoundedSourceResponse, SourceResponseKind, SourceWorkerLimits,
    HfHttpRequestPlan, HfRedirectPolicy, HfCredentialScope, validate_resolved_addresses,
};
fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let req = HfHttpRequestPlan {
        host: "cas-server.xethub.hf.co".into(),
        path_and_query: "/v2/reconstructions/abc".into(),
        range_header: Some("bytes=0-3".into()),
        credential_scope: HfCredentialScope::XetRead,
        redirect_policy: HfRedirectPolicy::Reject,
        max_response_bytes: 1024,
    };
    let mut r = BoundedSourceResponse::begin(
        &req, SourceWorkerLimits::default(),
        SourceResponseKind::ExactRange, 206, Some(4), Some(4))?;
    r.push(&[1,2])?;
    r.push(&[3,4])?;
    if r.finish()? != [1,2,3,4] { return Err("range mismatch".into()); }
    if validate_resolved_addresses(&["127.0.0.1".parse()?]).is_ok() {
        return Err("loopback DNS allowed".into());
    }
    println!("Jend Source Worker bounded response gate: PASS");
    println!("Jend Source Worker local DNS rejection: PASS");
    Ok(())
}
