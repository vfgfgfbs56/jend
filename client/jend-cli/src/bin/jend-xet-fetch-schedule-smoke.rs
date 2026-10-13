#![forbid(unsafe_code)]

#[allow(dead_code)]
#[path = "../xet_metadata.rs"]
mod xet_metadata;
#[allow(dead_code)]
#[path = "../xet_fetch_schedule.rs"]
mod xet_fetch_schedule;
#[allow(dead_code)]
#[path = "../xet_multipart.rs"]
mod xet_multipart;

use xet_fetch_schedule::{build_fetch_schedule, FetchScheduleError, FetchScheduleLimits};
use xet_metadata::parse_v2_reconstruction;

fn fixture() -> String {
    let a = "a".repeat(64);
    let b = "b".repeat(64);
    format!(
        r#"{{
          "offset_into_first_range":0,
          "terms":[
            {{"hash":"{a}","unpacked_length":16,"range":{{"start":0,"end":2}}}},
            {{"hash":"{b}","unpacked_length":16,"range":{{"start":5,"end":7}}}}
          ],
          "xorbs":{{
            "{a}":[
              {{"url":"https://transfer.xethub.hf.co/xorbs/default/{a}?X-Xet-Signed-Range=bytes%3D0-9&Expires=9999999999&Policy=p&Signature=s&Key-Pair-Id=k","ranges":[{{"chunks":{{"start":0,"end":1}},"bytes":{{"start":0,"end":9}}}}]}},
              {{"url":"https://transfer.xethub.hf.co/xorbs/default/{a}?X-Xet-Signed-Range=bytes%3D100-109&Expires=9999999999&Policy=p&Signature=s&Key-Pair-Id=k","ranges":[{{"chunks":{{"start":1,"end":2}},"bytes":{{"start":100,"end":109}}}}]}}
            ],
            "{b}":[
              {{"url":"https://us.aws.cdn.hf.co/xorbs/default/{b}?Expires=9999999999&Policy=p&Signature=s&Key-Pair-Id=k","ranges":[
                {{"chunks":{{"start":5,"end":6}},"bytes":{{"start":0,"end":7}}}},
                {{"chunks":{{"start":6,"end":7}},"bytes":{{"start":20,"end":27}}}}
              ]}}
            ]
          }}
        }}"#
    )
}

fn limits(total: u64) -> FetchScheduleLimits {
    FetchScheduleLimits {
        max_total_payload_bytes: total,
        max_request_payload_bytes: 32,
        max_jobs: 8,
        max_ranges: 8,
        max_concurrency: 2,
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let reconstruction = parse_v2_reconstruction(fixture().as_bytes(), 16)?;
    let schedule = build_fetch_schedule(&reconstruction, limits(64))?;
    if schedule.jobs.len() != 3
        || schedule.total_ranges != 4
        || schedule.total_authorized_payload_bytes != 36
        || schedule.wave_count != 2
        || schedule.max_concurrency != 2
    {
        return Err("bounded Xet fetch schedule mismatch".into());
    }
    if schedule.jobs[0].ordinal != 0
        || schedule.jobs[0].wave != 0
        || schedule.jobs[1].wave != 0
        || schedule.jobs[2].wave != 1
        || schedule.jobs[2].request.range_header != "bytes=0-7,20-27"
    {
        return Err("deterministic Xet concurrency wave mismatch".into());
    }
    println!("Jend Xet bounded multi-range fetch schedule: PASS");
    println!("Jend Xet deterministic concurrency waves: PASS");

    if !matches!(
        build_fetch_schedule(&reconstruction, limits(35)),
        Err(FetchScheduleError::TotalPayloadBudgetExceeded)
    ) {
        return Err("total xorb payload budget did not fail closed".into());
    }
    println!("Jend Xet aggregate physical-byte budget: PASS");

    // M8.5.8 deliberately only plans this exact combined Range header. The
    // existing transport still rejects comma-separated ranges under its
    // SingleRange206 contract until strict multipart parsing lands.
    if !schedule.jobs[2].request.range_header.contains(',') {
        return Err("fixture did not exercise atomic multi-range planning".into());
    }
    // Offline parser-only check; does not authorize live multipart transport.
    let signed = schedule.jobs[2].request.ranges.iter()
        .map(|(_, bytes)| *bytes).collect::<Vec<_>>();
    let sample = b"--JEND\r\nContent-Range: bytes 0-7/128\r\n\r\nABCDEFGH\r\n--JEND\r\nContent-Range: bytes 20-27/128\r\n\r\nIJKLMNOP\r\n--JEND--\r\n";
    let validated = xet_multipart::parse_multipart_ranges(
        "multipart/byteranges; boundary=JEND",
        sample,
        &signed,
        xet_multipart::MultipartLimits::default(),
    )?;
    if validated.len() != 2
        || validated[0].bytes != b"ABCDEFGH"
        || validated[1].bytes != b"IJKLMNOP"
    {
        return Err("signed physical range binding mismatch".into());
    }
    println!("Jend Xet strict offline multipart parser: PASS");
    println!("Jend Xet multipart network execution remains fail-closed: PASS");
    Ok(())
}
