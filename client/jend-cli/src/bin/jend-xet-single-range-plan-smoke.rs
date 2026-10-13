#![forbid(unsafe_code)]

#[allow(dead_code)]
#[path = "../xet_metadata.rs"]
mod xet_metadata;

use xet_metadata::{parse_v2_reconstruction, ParseError};

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let hash = "a".repeat(64);
    let body = format!(
        r#"{{
          "offset_into_first_range": 0,
          "terms": [{{
            "hash": "{hash}",
            "unpacked_length": 65536,
            "range": {{"start": 0, "end": 1}}
          }}],
          "xorbs": {{
            "{hash}": [{{
              "url": "https://transfer.xethub.hf.co/xorbs/default/{hash}?X-Xet-Signed-Range=bytes%3D1024-2047&Expires=9999999999&Policy=p&Signature=s&Key-Pair-Id=k",
              "ranges": [{{
                "chunks": {{"start": 0, "end": 1}},
                "bytes": {{"start": 1024, "end": 2047}}
              }}]
            }}]
          }}
        }}"#
    );
    let parsed = parse_v2_reconstruction(body.as_bytes(), 1)?;
    let request = parsed.fetches[0].single_range_request()?;
    if request.host != "transfer.xethub.hf.co"
        || request.range_header != "bytes=1024-2047"
        || request.expected_len != 1024
    {
        return Err("single-range execution plan drift".into());
    }

    let multi = format!(
        r#"{{
          "offset_into_first_range": 0,
          "terms": [{{
            "hash": "{hash}",
            "unpacked_length": 131072,
            "range": {{"start": 0, "end": 2}}
          }}],
          "xorbs": {{
            "{hash}": [{{
              "url": "https://transfer.xethub.hf.co/xorbs/default/{hash}?X-Xet-Signed-Range=bytes%3D1024-2047%2C4096-8191&Expires=9999999999&Policy=p&Signature=s&Key-Pair-Id=k",
              "ranges": [
                {{
                  "chunks": {{"start": 0, "end": 1}},
                  "bytes": {{"start": 1024, "end": 2047}}
                }},
                {{
                  "chunks": {{"start": 1, "end": 2}},
                  "bytes": {{"start": 4096, "end": 8191}}
                }}
              ]
            }}]
          }}
        }}"#
    );
    let parsed_multi = parse_v2_reconstruction(multi.as_bytes(), 1)?;
    if !matches!(
        parsed_multi.fetches[0].single_range_request(),
        Err(ParseError::SingleRangeRequired)
    ) {
        return Err("multi-range fetch escaped single-range gate".into());
    }

    println!("Jend Xet single-range execution plan: PASS");
    println!("Jend Xet multi-range execution remains fail-closed: PASS");
    Ok(())
}
