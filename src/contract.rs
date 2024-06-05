use cosmwasm_std::{
    entry_point, from_binary, to_binary, Addr, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdError, StdResult, WasmMsg, BankMsg, Coin,
};
use cw2::set_contract_version;
use cw20::{Cw20ReceiveMsg, Cw20ExecuteMsg};
use cw721::Cw721ReceiveMsg;
use crate::error::{self, ContractError};
use crate::msg::{ClaimMsg, ExecuteMsg, InstantiateMsg, MintMsg, PolicyMetadata, QueryMsg, PolicyResponse, AllPoliciesResponse, ConfigResponse};
use crate::state::{InsurancePolicy, INSURANCE_POLICIES, CW20_TOKEN_ADDRESS, CW721_CONTRACT_ADDRESS, TREASURY_ADDRESS};

// version info for migration
const CONTRACT_NAME: &str = "crates.io:cosmwasm-insurance";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[entry_point]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
    CW20_TOKEN_ADDRESS.save(deps.storage, &msg.cw20_token_address)?;
    CW721_CONTRACT_ADDRESS.save(deps.storage, &msg.cw721_contract_address)?;
    TREASURY_ADDRESS.save(deps.storage, &msg.treasury_address)?;

    Ok(Response::new()
        .add_attribute("method", "instantiate")
        .add_attribute("cw20_token_address", msg.cw20_token_address)
        .add_attribute("cw721_contract_address", msg.cw721_contract_address)
        .add_attribute("treasury_address", msg.treasury_address))
}

#[entry_point]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::CreatePolicy {
            policy_id,
            insured_amount,
            premium,
            condition,
            premium_frequency,
            policy_term,
            riders,
        } => execute_create_policy(
            deps,
            info,
            policy_id,
            insured_amount,
            premium,
            condition,
            premium_frequency,
            policy_term,
            riders,
        ),
        ExecuteMsg::Claim { policy_id } => execute_claim(deps, info, policy_id),
        ExecuteMsg::Receive(cw20_msg) => execute_receive_cw20(deps, info, cw20_msg),
        ExecuteMsg::ReceiveNft(cw721_msg) => execute_receive_nft(deps, info, cw721_msg),
        ExecuteMsg::PayPremium { policy_id, amount } => execute_pay_premium(deps, info, policy_id, amount),
    }
}

pub fn execute_create_policy(
    deps: DepsMut,
    info: MessageInfo,
    policy_id: String,
    insured_amount: u128,
    premium: u128,
    premium_frequency: String,
    policy_term: String,
    condition: String,
    riders: Vec<String>,
) -> Result<Response, ContractError> {
    let policy = InsurancePolicy {
        policy_id: policy_id.clone(),
        insured_amount,
        premium,
        premium_frequency: premium_frequency.clone(),
        policy_term: policy_term.clone(),
        owner: info.sender.clone(),
        claimed: false,
        condition: condition.clone(),
        riders: riders.clone(),
    };

    INSURANCE_POLICIES.save(deps.storage, &policy_id, &policy)?;

    // Mint NFT
    let cw721_contract_address = CW721_CONTRACT_ADDRESS.load(deps.storage)?;
    let mint_msg = MintMsg::<PolicyMetadata> {
        token_id: policy_id.clone(),
        owner: info.sender.to_string(),
        token_uri: None,
        extension: PolicyMetadata {
            policy_id: policy_id.clone(),
            insured_amount,
            premium,
            premium_frequency,
            policy_term,
            condition,
            riders,
        },
    };
    let wasm_msg = WasmMsg::Execute {
        contract_addr: cw721_contract_address.into(),
        msg: to_binary(&mint_msg)?,
        funds: vec![],
    };

    Ok(Response::new()
        .add_message(wasm_msg)
        .add_attribute("method", "execute_create_policy")
        .add_attribute("policy_id", policy_id)
        .add_attribute("insured_amount", insured_amount.to_string())
        .add_attribute("premium", premium.to_string())
        .add_attribute("owner", info.sender.to_string()))
}


pub fn execute_claim(deps: DepsMut, info: MessageInfo, policy_id: String) -> Result<Response, ContractError> {
    let mut policy = INSURANCE_POLICIES.load(deps.storage, &policy_id)?;

    if policy.owner != info.sender {
        return Err(ContractError::Unauthorized {});
    }

    if policy.claimed {
        return Err(error::ContractError::Std(StdError::generic_err("Policy already claimed")));
    }

    // Check the predefined condition
    if !verify_condition(&policy.condition) {
        return Err(ContractError::Std(StdError::generic_err("Claim condition not met")));
    }

    let cw20_token_address = CW20_TOKEN_ADDRESS.load(deps.storage)?;
    policy.claimed = true;
    INSURANCE_POLICIES.save(deps.storage, &policy_id, &policy)?;

    // Construct message to send payout
    let send_msg = WasmMsg::Execute {
        contract_addr: cw20_token_address.into(),
        msg: to_binary(&Cw20ExecuteMsg::Transfer {
            recipient: info.sender.to_string(),
            amount: policy.insured_amount.into(),
        })?,
        funds: vec![],
    };

    Ok(Response::new()
        .add_message(send_msg)
        .add_attribute("method", "execute_claim")
        .add_attribute("policy_id", policy_id))
}

fn verify_condition(condition: &str) -> bool {
    // Placeholder: Implement actual condition verification logic
    condition == "standard_condition"
}

pub fn execute_receive_cw20(
    deps: DepsMut,
    info: MessageInfo,
    cw20_msg: Cw20ReceiveMsg,
) -> Result<Response, ContractError> {
    let cw20_token_address = CW20_TOKEN_ADDRESS.load(deps.storage)?;

    if info.sender != cw20_token_address {
        return Err(ContractError::Unauthorized {});
    }

    match from_binary(&cw20_msg.msg) {
        Ok(ClaimMsg { policy_id }) => execute_claim(deps, MessageInfo { sender: info.sender, funds: vec![] }, policy_id),
        _ => Err(error::ContractError::Std(StdError::generic_err("Invalid CW20 message"))),
    }
}

pub fn execute_receive_nft(
    deps: DepsMut,
    info: MessageInfo,
    cw721_msg: Cw721ReceiveMsg,
) -> Result<Response, ContractError> {
    let cw721_contract_address = CW721_CONTRACT_ADDRESS.load(deps.storage)?;

    if info.sender != cw721_contract_address {
        return Err(ContractError::Unauthorized {});
    }

    Ok(Response::new()
        .add_attribute("method", "execute_receive_nft")
        .add_attribute("token_id", cw721_msg.token_id))
}

pub fn execute_pay_premium(
    deps: DepsMut,
    info: MessageInfo,
    policy_id: String,
    amount: u128,
) -> Result<Response, ContractError> {
    let treasury_address = TREASURY_ADDRESS.load(deps.storage)?;

    let policy = INSURANCE_POLICIES.load(deps.storage, &policy_id)?;
    if policy.owner != info.sender {
        return Err(ContractError::Unauthorized {});
    }

    // Send the premium to the treasury
    let send_msg = BankMsg::Send {
        to_address: treasury_address.clone(),
        amount: vec![Coin {
            denom: "uatom".to_string(),  // Adjust the token denom as needed
            amount: amount.into(),
        }],
    };

    Ok(Response::new()
        .add_message(send_msg)
        .add_attribute("method", "execute_pay_premium")
        .add_attribute("policy_id", policy_id)
        .add_attribute("amount", amount.to_string())
        .add_attribute("treasury_address", treasury_address))
}

#[entry_point]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetPolicy { policy_id } => to_binary(&query_policy(deps, policy_id)?),
        QueryMsg::GetAllPolicies {} => to_binary(&query_all_policies(deps)?),
        QueryMsg::GetConfig {} => to_binary(&query_config(deps)?),
    }
}

fn query_policy(deps: Deps, policy_id: String) -> StdResult<PolicyResponse> {
    let policy = INSURANCE_POLICIES.load(deps.storage, &policy_id)?;
    Ok(PolicyResponse {
        policy_id: policy.policy_id,
        insured_amount: policy.insured_amount,
        premium: policy.premium,
        premium_frequency: policy.premium_frequency,
        policy_term: policy.policy_term,
        owner: policy.owner.to_string(),
        claimed: policy.claimed,
        condition: policy.condition,
        riders: policy.riders,
    })
}

fn query_all_policies(deps: Deps) -> StdResult<AllPoliciesResponse> {
    let policies = INSURANCE_POLICIES
        .range(deps.storage, None, None, cosmwasm_std::Order::Ascending)
        .map(|item| {
            let (_key, policy) = item?;
            Ok(PolicyResponse {
                policy_id: policy.policy_id,
                insured_amount: policy.insured_amount,
                premium: policy.premium,
                premium_frequency: policy.premium_frequency,
                policy_term: policy.policy_term,
                owner: policy.owner.to_string(),
                claimed: policy.claimed,
                condition: policy.condition,
                riders: policy.riders,
            })
        })
        .collect::<StdResult<Vec<_>>>()?;
    Ok(AllPoliciesResponse { policies })
}


fn query_config(deps: Deps) -> StdResult<ConfigResponse> {
    let cw20_token_address = CW20_TOKEN_ADDRESS.load(deps.storage)?;
    let cw721_contract_address = CW721_CONTRACT_ADDRESS.load(deps.storage)?;
    let treasury_address = TREASURY_ADDRESS.load(deps.storage)?;
    Ok(ConfigResponse {
        cw20_token_address,
        cw721_contract_address,
        treasury_address,
    })
}

#[cfg(test)]
mod tests {
    // Add tests here
}
