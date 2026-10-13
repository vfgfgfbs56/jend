#![forbid(unsafe_code)]

use sqlx::{migrate::Migrator, postgres::PgPoolOptions};

static MIGRATOR: Migrator = sqlx::migrate!("../../deployment/postgres");

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let database_url = std::env::var("DATABASE_URL")?;
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url)
        .await?;
    MIGRATOR.run(&pool).await?;
    eprintln!("Jend database migrations applied");
    Ok(())
}
