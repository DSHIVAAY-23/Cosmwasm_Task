use cosmwasm_std::Addr;
use cw_storage_plus::{Item, Map};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct InsurancePolicy {
    pub policy_id: String,
    pub insured_amount: u128,
    pub premium: u128,
    pub premium_frequency: String, 
    pub policy_term: String, 
    pub riders: Vec<String>, 
    pub owner: Addr,
    pub claimed: bool,
    pub condition: String,  
}

pub const INSURANCE_POLICIES: Map<&str, InsurancePolicy> = Map::new("insurance_policies");
pub const CW20_TOKEN_ADDRESS: Item<String> = Item::new("cw20_token_address");
pub const CW721_CONTRACT_ADDRESS: Item<String> = Item::new("cw721_contract_address");
pub const TREASURY_ADDRESS: Item<String> = Item::new("treasury_address");
