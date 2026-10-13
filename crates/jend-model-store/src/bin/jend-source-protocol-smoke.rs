#![forbid(unsafe_code)]

use jend_model_store::{
    ModelId, ModelReleaseSigningKey, ModelSourceMap, PageSourceBinding, SourceDescriptor,
    SourceOrigin, WeightPageDescriptor, WeightPageId,
};

fn page(seed: u8, len: usize) -> WeightPageDescriptor {
    let payload = vec![seed; len];
    WeightPageDescriptor {
        page_id: WeightPageId::for_bytes(&payload),
        plaintext_len: len as u64,
    }
}

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let hf = SourceDescriptor {
        origin: SourceOrigin::HuggingFaceXet {
            repo_id: "org/huge-model".into(),
            commit_sha: "0123456789abcdef0123456789abcdef01234567".into(),
            file_path: "model-00001-of-00128.safetensors".into(),
        },
        object_len: 8 * 1024 * 1024 * 1024,
        whole_object_sha256: None,
    };
    let publisher = SourceDescriptor {
        origin: SourceOrigin::PublisherHttps {
            host: "weights.example.com".into(),
            immutable_path: "/releases/v1/model-00001.safetensors".into(),
        },
        object_len: 8 * 1024 * 1024 * 1024,
        whole_object_sha256: Some([0x44; 32]),
    };

    let selected_page = page(0xA7, 4 * 1024 * 1024);
    let hf_id = hf.source_id()?;
    let publisher_id = publisher.source_id()?;

    let map = ModelSourceMap {
        model_id: ModelId([83u8; 16]),
        release_sequence: 1,
        sources: vec![hf, publisher],
        bindings: vec![
            PageSourceBinding {
                page: selected_page,
                source_id: hf_id,
                source_offset: 6 * 1024 * 1024 * 1024,
            },
            PageSourceBinding {
                page: selected_page,
                source_id: publisher_id,
                source_offset: 2 * 1024 * 1024 * 1024,
            },
        ],
    };
    map.validate()?;

    let signing = ModelReleaseSigningKey::generate()?;
    let public = signing.public_key();
    let signed = signing.sign_source_map(map)?;
    public.verify_source_map(&signed)?;

    let wire = signed.encode_wire()?;
    let decoded = jend_model_store::SignedModelSourceMap::decode_wire(&wire)?;
    public.verify_source_map(&decoded)?;

    let candidates = decoded.map.bindings_for_page(selected_page.page_id);
    if candidates.len() != 2 {
        return Err("source map did not preserve two independent origins".into());
    }

    let request = decoded.map.read_request(selected_page.page_id, hf_id)?;
    if request.len != 4 * 1024 * 1024
        || request.source_offset != 6 * 1024 * 1024 * 1024
        || request.expected_page != selected_page
    {
        return Err("typed source read request lost page/range identity".into());
    }

    // The protocol request is intentionally URL-free. Network adapters receive
    // the signed source descriptor separately and construct only their own
    // typed upstream request.
    let mut tampered = decoded.clone();
    tampered.map.bindings[0].source_offset += 4096;
    if public.verify_source_map(&tampered).is_ok() {
        return Err("signed source-map range tampering was not detected".into());
    }

    let invalid = SourceDescriptor {
        origin: SourceOrigin::HuggingFaceXet {
            repo_id: "org/huge-model".into(),
            commit_sha: "main".into(),
            file_path: "../secret".into(),
        },
        object_len: 1,
        whole_object_sha256: None,
    };
    if invalid.validate().is_ok() {
        return Err("mutable/path-traversal source descriptor was accepted".into());
    }

    println!(
        "Jend source protocol: origins={}, page_mib={}, typed_range_mib={}",
        decoded.map.sources.len(),
        selected_page.plaintext_len / (1024 * 1024),
        request.len / (1024 * 1024),
    );
    println!("Jend URL-free immutable source descriptors: PASS");
    println!("Jend signed multi-origin page/range binding: PASS");
    println!("Jend WeightVM source independence contract: PASS");
    Ok(())
}
