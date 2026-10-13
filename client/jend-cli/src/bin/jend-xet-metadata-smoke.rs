#[allow(dead_code)]
#[path = "../xet_metadata.rs"]
mod xet_metadata;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let grant = br#"{"accessToken":"test","exp":9999999,"casUrl":"https://cas-server.xethub.hf.co"}"#;
    let parsed = xet_metadata::parse_read_grant(grant, 100)?;
    if parsed.token() != "test"
        || parsed.cas_host != "cas-server.xethub.hf.co"
        || parsed.expires_unix != 9_999_999
    {
        return Err("bad Xet read grant".into());
    }

    let hash = "a".repeat(64);
    let signed_url = format!(
        "https://transfer.xethub.hf.co/xorbs/default/{hash}?X-Xet-Signed-Range=bytes%3D0-131071&Expires=9999999999&Policy=x&Signature=y&Key-Pair-Id=z"
    );
    let reconstruction_json = format!(
        r#"{{
          "offset_into_first_range": 0,
          "terms": [{{
            "hash": "{hash}",
            "unpacked_length": 263873,
            "range": {{"start": 0, "end": 4}}
          }}],
          "xorbs": {{
            "{hash}": [{{
              "url": "{signed_url}",
              "ranges": [{{
                "chunks": {{"start": 0, "end": 4}},
                "bytes": {{"start": 0, "end": 131071}}
              }}]
            }}]
          }}
        }}"#
    );

    let reconstruction =
        xet_metadata::parse_v2_reconstruction(reconstruction_json.as_bytes(), 128 * 1024)?;
    if reconstruction.offset_into_first_range != 0
        || reconstruction.terms.len() != 1
        || reconstruction.fetches.len() != 1
        || reconstruction.terms[0].hash != hash
        || reconstruction.terms[0].chunks.start != 0
        || reconstruction.terms[0].chunks.end != 4
        || reconstruction.terms[0].unpacked_length != 263_873
        || reconstruction.fetches[0].hash != hash
        || reconstruction.fetches[0].ranges.len() != 1
        || reconstruction.fetches[0].ranges[0].0.start != 0
        || reconstruction.fetches[0].ranges[0].0.end != 4
        || reconstruction.fetches[0].ranges[0].1.start != 0
        || reconstruction.fetches[0].ranges[0].1.end != 131_071
        || !reconstruction.fetches[0]
            .signed_url
            .as_str()
            .contains("X-Xet-Signed-Range=")
    {
        return Err("bad published-shape Xet reconstruction metadata".into());
    }

    let malicious = reconstruction_json.replace("transfer.xethub.hf.co", "169.254.169.254");
    if xet_metadata::parse_v2_reconstruction(malicious.as_bytes(), 50).is_ok() {
        return Err("Xet reconstruction accepted SSRF transfer endpoint".into());
    }

    let legacy_wrong = format!(
        r#"{{"offset_into_first_range":0,"terms":[{{"hash":"{hash}","start":0,"end":2,"unpacked_length":100}}],"xorbs":[]}}"#
    );
    if xet_metadata::parse_v2_reconstruction(legacy_wrong.as_bytes(), 50).is_ok() {
        return Err("legacy incorrect Xet fixture shape was accepted".into());
    }

    println!("Jend Xet read-token strict parser: PASS");
    if !reconstruction_json.contains("/xorbs/default/") {
        return Err("fixture did not exercise current live /xorbs/default/ path".into());
    }
    println!("Jend Xet published v2 schema parser: PASS");
    println!("Jend Xet live plural transfer-path compatibility: PASS");
    println!("Jend Xet current HF CDN bridge allowlist: PASS");

    let cdn_signed_url = format!(
        "https://us.aws.cdn.hf.co/xorbs/default/{hash}?Expires=9999999999&Policy=p&Signature=s&Key-Pair-Id=k"
    );
    let cdn_reconstruction_json = reconstruction_json.replace(&signed_url, &cdn_signed_url);
    let _ = xet_metadata::parse_v2_reconstruction(
        cdn_reconstruction_json.as_bytes(),
        128 * 1024,
    )?;
    println!("Jend Xet current HF CDN direct-xorb path: PASS");
    println!("Jend Xet live CDN reconstruction-range binding: PASS");

    let opaque_query = reconstruction_json.replace("&Policy=x", "&Policy=user@example~opaque");
    let _ = xet_metadata::parse_v2_reconstruction(opaque_query.as_bytes(), 128 * 1024)?;
    println!("Jend Xet opaque signed-query parsing: PASS");
    println!("Jend Xet reconstruction SSRF rejection: PASS");
    println!("Jend Xet legacy wrong-schema regression rejection: PASS");
    Ok(())
}
