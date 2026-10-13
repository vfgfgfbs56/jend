#![forbid(unsafe_code)]
// Offline proof that two different signed URL grants stay independent and
// assemble into one logical interval. No HTTP requests and no WeightVM.
#[allow(dead_code)]
#[path = "../source_worker_transport.rs"]
mod source_worker_transport;
#[allow(dead_code)]
#[path = "../xet_metadata.rs"]
mod xet_metadata;
#[allow(dead_code)]
#[path = "../xet_fetch_schedule.rs"]
mod xet_fetch_schedule;
#[allow(dead_code)]
#[path = "../xet_multipart.rs"]
mod xet_multipart;
#[allow(dead_code)]
#[path = "../xet_multi_fetch_transport.rs"]
mod xet_multi_fetch_transport;
#[allow(dead_code)]
#[path = "../xet_signed_fetch_executor.rs"]
mod xet_signed_fetch_executor;
#[allow(dead_code)]
#[path = "../xorb_decode.rs"]
mod xorb_decode;
#[allow(dead_code)]
#[path = "../xet_multi_decode.rs"]
mod xet_multi_decode;

use xet_fetch_schedule::{build_fetch_schedule, FetchScheduleLimits};
use xet_metadata::parse_v2_reconstruction;
use xet_multi_decode::decode_untrusted_multipart_ranges;
use xet_signed_fetch_executor::{
    validate_schedule, validate_signed_single_range_body, SequentialFetchLimits,
};
use xorb_decode::reconstruct_slice_from_ranges;

fn record(bytes: &[u8]) -> Vec<u8> {
    let n = bytes.len();
    let mut b = vec![0, n as u8, 0, 0, 0, n as u8, 0, 0];
    b.extend_from_slice(bytes);
    b
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let hash = "a".repeat(64);
    let metadata = format!(
        r#"{{"offset_into_first_range":0,
          "terms":[
            {{"hash":"{hash}","unpacked_length":3,"range":{{"start":0,"end":1}}}},
            {{"hash":"{hash}","unpacked_length":3,"range":{{"start":1,"end":2}}}}
          ],
          "xorbs":{{"{hash}":[
            {{"url":"https://us.aws.cdn.hf.co/xorbs/default/{hash}?Expires=9999999999&Policy=p&Signature=s&Key-Pair-Id=k",
              "ranges":[{{"chunks":{{"start":0,"end":1}},"bytes":{{"start":0,"end":10}}}}]}},
            {{"url":"https://us.aws.cdn.hf.co/xorbs/default/{hash}?Expires=9999999999&Policy=p2&Signature=s2&Key-Pair-Id=k",
              "ranges":[{{"chunks":{{"start":1,"end":2}},"bytes":{{"start":20,"end":30}}}}]}}
          ]}}}}"#
    );
    let reconstruction = parse_v2_reconstruction(metadata.as_bytes(), 6)?;
    let schedule = build_fetch_schedule(
        &reconstruction,
        FetchScheduleLimits {
            max_total_payload_bytes: 22,
            max_request_payload_bytes: 11,
            max_jobs: 2,
            max_ranges: 2,
            max_concurrency: 1,
        },
    )?;
    let limits = SequentialFetchLimits {
        max_total_physical_bytes: 22,
        max_jobs: 2,
        max_framing_per_job: 512,
        connect_timeout_ms: 1000,
        request_timeout_ms: 2000,
    };
    validate_schedule(&schedule, limits)?;
    let mut untrusted = Vec::new();
    for (job, (raw, content_range)) in schedule.jobs.iter().zip([
        (record(b"abc"), "bytes 0-10/100"),
        (record(b"def"), "bytes 20-30/100"),
    ]) {
        let checked = validate_signed_single_range_body(
            &job.request,
            reqwest::StatusCode::PARTIAL_CONTENT,
            content_range,
            raw,
            limits.max_total_physical_bytes,
        )?;
        untrusted.push(checked);
    }
    let decoded = decode_untrusted_multipart_ranges(untrusted, 22, 6)?;
    let logical = reconstruct_slice_from_ranges(&reconstruction, &decoded, 6, 6)?;
    if logical != b"abcdef" {
        return Err("separate signed Xet fetch entry logical reconstruction mismatch".into());
    }
    println!("Jend Xet separate signed singleton entries: PASS");
    println!("Jend Xet exact single Content-Range binding: PASS");
    println!("Jend Xet bounded scheduled logical assembler: PASS");
    println!("Jend Xet scheduled unverified bytes kept outside WeightVM: PASS");
    if validate_signed_single_range_body(
        &schedule.jobs[0].request,
        reqwest::StatusCode::OK,
        "bytes 0-10/100",
        record(b"abc"),
        22,
    ).is_ok() {
        return Err("HTTP 200 accepted by signed singleton gate".into());
    }
    println!("Jend Xet scheduled HTTP 200 fallback rejected: PASS");
    Ok(())
}
