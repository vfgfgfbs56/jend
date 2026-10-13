#![forbid(unsafe_code)]

use jend_model_store::{
    HfRedirectPolicy, HfXetAdapterPolicy, HfXetReadGrant, HfXetRequestPlanner,
    SourceDescriptor, SourceOrigin, SourceReadRequest, WeightPageDescriptor, WeightPageId,
    XetByteRange, XetChunkRange, XetFetchMetadata, XetRangeMetadata, XetTermMetadata,
};

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let page = WeightPageDescriptor {
        page_id: WeightPageId([7u8; 32]),
        plaintext_len: 128 * 1024,
    };
    let source = SourceDescriptor {
        origin: SourceOrigin::HuggingFaceXet {
            repo_id: "org/model".into(),
            commit_sha: "0123456789abcdef0123456789abcdef01234567".into(),
            file_path: "model-00001-of-00016.safetensors".into(),
        },
        object_len: 128 * 1024 * 1024,
        whole_object_sha256: None,
    };
    let request = SourceReadRequest {
        source_id: source.source_id()?,
        source_offset: 8 * 1024 * 1024,
        len: page.plaintext_len,
        expected_page: page,
    };
    let planner = HfXetRequestPlanner::new(&source, request, HfXetAdapterPolicy::default())?;

    let resolve = planner.resolve_request();
    if resolve.host != "huggingface.co"
        || resolve.redirect_policy != HfRedirectPolicy::Reject
        || !resolve.path_and_query.contains(
            "/resolve/0123456789abcdef0123456789abcdef01234567/",
        )
    {
        return Err("HF/Xet resolve request escaped immutable/no-redirect policy".into());
    }

    let file_hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let file_id = planner.accept_resolve_response(302, Some(file_hash))?;
    let grant = HfXetReadGrant::from_token_fields(
        "xet_short_lived_read_token".into(),
        10_000,
        "https://cas-server.xethub.hf.co",
        100,
    )?;
    let reconstruction = planner.reconstruction_v2_request(file_id, &grant, 100)?;
    if reconstruction.range_header.as_deref() != Some("bytes=8388608-8519679") {
        return Err("HF/Xet reconstruction range is not bound to the Jend page request".into());
    }

    let xorb_hash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let signed_url = format!(
        "https://transfer.xethub.hf.co/xorbs/default/{xorb_hash}?X-Xet-Signed-Range=bytes%3D1024-66559&Expires=9999999999&Policy=x&Signature=y&Key-Pair-Id=z"
    );
    let plan = planner.validate_v2_reconstruction(
        0,
        &[XetTermMetadata {
            xorb_hash: xorb_hash.into(),
            chunks: XetChunkRange { start: 10, end: 12 },
            unpacked_length: page.plaintext_len,
        }],
        vec![XetFetchMetadata::new(
            xorb_hash.into(),
            signed_url,
            vec![XetRangeMetadata {
                chunks: XetChunkRange { start: 10, end: 12 },
                bytes: XetByteRange { start: 1024, end: 66_559 },
            }],
        )],
    )?;
    if plan.output_len != page.plaintext_len
        || plan.fetches().len() != 1
        || plan.fetches()[0].range_header() != "bytes=1024-66559"
    {
        return Err("HF/Xet reconstruction planner contract failed".into());
    }

    let malicious = XetFetchMetadata::new(
        xorb_hash.into(),
        format!("https://169.254.169.254/xorbs/default/{xorb_hash}?X-Xet-Signed-Range=x"),
        vec![XetRangeMetadata {
            chunks: XetChunkRange { start: 10, end: 12 },
            bytes: XetByteRange { start: 1024, end: 66_559 },
        }],
    );
    if planner.validate_v2_reconstruction(
        0,
        &[XetTermMetadata {
            xorb_hash: xorb_hash.into(),
            chunks: XetChunkRange { start: 10, end: 12 },
            unpacked_length: page.plaintext_len,
        }],
        vec![malicious],
    ).is_ok() {
        return Err("HF/Xet adapter accepted a non-HF signed transfer host".into());
    }

    println!("Jend HF/Xet immutable discovery/range planner: PASS");
    println!("Jend HF/Xet signed-transfer allowlist/budget policy: PASS");
    println!("Jend HF/Xet adapter carries no executable redirect: PASS");
    Ok(())
}
