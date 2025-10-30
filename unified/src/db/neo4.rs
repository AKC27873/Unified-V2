use reqwest::Client;
use serde_json::{json, Value};

pub struct Neo4jClient {
	base: String, // This will be the host 
	user: String,
	pass: String,
    client: Client,
}


impl Neo4jClient {
	pub fn new(base: &str, user: &str, pass: &str) -> Self {
		self {
			base: base.trim_end_matches('/').to_string(),
			user: user.to_string(),
			pass: pass.to_string(),
			client: Client::new()
		}
	}
	pub async fn run_statement(&self, statement: &str, params: serde_json::Value) -> anyhow::Result<Value> {

		let url = format!("{}/db/neo4j/tx/commit", self.base);
		let body = json!({
			"statements": [
				{
					"statement": statement,
					"parameters": params
				}
			]

		});	
	
		let res = self
			.client
			.post(&url) 
			.basic_auth (&self.user, Some(&self.pass))
			.json(&body)
			.send()
			.await?;

		let j: Value = res.json().await?;
		Ok(j)


	}







}
