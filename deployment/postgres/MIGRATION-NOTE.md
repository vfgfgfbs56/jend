# Migration numbering

M5.4 normalizes the pre-release migration sequence so every SQLx version is
unique:

1. `001_control_plane.sql`
2. `002_admission.sql`
3. `003_sync_relay.sql`
4. `004_auth_http.sql`
5. `005_device_binding.sql`
6. `006_jreq.sql`

The older `003_model_store.sql` draft was retired because its model schema
conflicted with the canonical model tables already created in migration 001.

This project has not reached a production migration compatibility guarantee.
Discard/reset pre-M5.4 development databases before running this sequence.
