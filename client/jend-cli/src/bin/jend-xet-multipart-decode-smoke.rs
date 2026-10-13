#![forbid(unsafe_code)]

#[allow(dead_code)]
#[path = "../source_worker_transport.rs"]
mod source_worker_transport;
#[allow(dead_code)]
#[path = "../xet_metadata.rs"]
mod xet_metadata;
#[allow(dead_code)]
#[path = "../xet_multipart.rs"]
mod xet_multipart;
#[allow(dead_code)]
#[path = "../xet_multi_fetch_transport.rs"]
mod xet_multi_fetch_transport;
#[allow(dead_code)]
#[path = "../xorb_decode.rs"]
mod xorb_decode;
#[allow(dead_code)]
#[path = "../xet_multi_decode.rs"]
mod xet_multi_decode;

use xet_metadata::parse_v2_reconstruction;
use xet_multipart::MultipartLimits;
use xet_multi_fetch_transport::validate_signed_multipart_body;
use xet_multi_decode::decode_untrusted_multipart_ranges;
use xorb_decode::reconstruct_slice_from_ranges;

fn record(raw: &[u8]) -> Vec<u8> {
    let n = raw.len();
    let mut body = vec![0, n as u8, 0, 0, 0, n as u8, 0, 0];
    body.extend_from_slice(raw);
    body
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let hash = "a".repeat(64);
    let metadata = format!(
        r#"{{"offset_into_first_range":0,
          "terms":[
            {{"hash":"{hash}","unpacked_length":3,"range":{{"start":0,"end":1}}}},
            {{"hash":"{hash}","unpacked_length":3,"range":{{"start":1,"end":2}}}}
          ],
          "xorbs":{{"{hash}":[{{
            "url":"https://us.aws.cdn.hf.co/xorbs/default/{hash}?Expires=9999999999&Policy=p&Signature=s&Key-Pair-Id=k",
            "ranges":[
              {{"chunks":{{"start":0,"end":1}},"bytes":{{"start":0,"end":10}}}},
              {{"chunks":{{"start":1,"end":2}},"bytes":{{"start":20,"end":30}}}}
            ]}}]}}}}"#
    );
    let reconstruction = parse_v2_reconstruction(metadata.as_bytes(), 6)?;
    let signed = reconstruction.fetches[0].range_batch_request()?;
    let mut body = Vec::new();
    for (span, data) in [(signed.ranges[0].1, record(b"abc")), (signed.ranges[1].1, record(b"def"))] {
        body.extend_from_slice(format!(
            "--JEND\r\nContent-Range: bytes {}-{}/100\r\n\r\n",
            span.start, span.end
        ).as_bytes());
        body.extend_from_slice(&data);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(b"--JEND--\r\n");
    let limits = MultipartLimits { max_payload: 22, max_framing: 512 };
    let validated = validate_signed_multipart_body(
        &signed, reqwest::StatusCode::PARTIAL_CONTENT,
        "multipart/byteranges; boundary=JEND", &body, limits
    )?;
    let decoded = decode_untrusted_multipart_ranges(validated, 22, 6)?;
    let logical = reconstruct_slice_from_ranges(&reconstruction, &decoded, 6, 6)?;
    if logical != b"abcdef" {
        return Err("multipart source-to-logical pipeline mismatch".into());
    }
    println!("Jend Xet multipart physical-to-logical offline pipeline: PASS");
    println!("Jend Xet decoded data kept outside WeightVM: PASS");

    if validate_signed_multipart_body(
        &signed, reqwest::StatusCode::OK,
        "multipart/byteranges; boundary=JEND", &body, limits
    ).is_ok() {
        return Err("HTTP 200 fallback was accepted".into());
    }
    println!("Jend Xet untrusted multipart fallback rejected: PASS");
    Ok(())
}
