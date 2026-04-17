sed -i 's/let mut header = 27 + u8::try_from(rec_id.to_i32()).unwrap();/let mut header = 27 + u8::try_from(rec_id.to_i32()).map_err(|e| format!("Invalid recovery ID: {e}"))?;/g' src/builder.rs
