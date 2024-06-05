use cosmwasm_std::Binary;
use cw20::Cw20ReceiveMsg;
use cw721::Cw721ReceiveMsg;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct InstantiateMsg {
    pub cw20_token_address: String,
    pub cw721_contract_address: String,
    pub treasury_address: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {
    CreatePolicy {
        policy_id: String,
        insured_amount: u128,
        premium: u128,
        premium_frequency: String,
        policy_term: String,
        condition: String,
        riders: Vec<String>,
    },
    Claim { policy_id: String },
    Receive(Cw20ReceiveMsg),
    ReceiveNft(Cw721ReceiveMsg),
    PayPremium { policy_id: String, amount: u128 },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct PolicyMetadata {
    pub policy_id: String,
    pub insured_amount: u128,
    pub premium: u128,
    pub premium_frequency: String, // New field
    pub policy_term: String, // New field
    pub condition: String,  // Condition as a string
    pub riders: Vec<String>, // New field
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct ClaimMsg {
    pub policy_id: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct MintMsg<T> {
    pub token_id: String,
    pub owner: String,
    pub token_uri: Option<String>,
    pub extension: T,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    GetPolicy { policy_id: String },
    GetAllPolicies {},
    GetConfig {},
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct PolicyResponse {
    pub policy_id: String,
    pub insured_amount: u128,
    pub premium: u128,
    pub premium_frequency: String, // New field
    pub policy_term: String, // New field
    pub owner: String,
    pub claimed: bool,
    pub condition: String,
    pub riders: Vec<String>, // New field
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct AllPoliciesResponse {
    pub policies: Vec<PolicyResponse>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct ConfigResponse {
    pub cw20_token_address: String,
    pub cw721_contract_address: String,
    pub treasury_address: String,
}

#[derive(Serialize, Deserialize)]
pub struct PayPremiumMsg {
    pub policy_id: String,
    pub amount: u128,
}
