#[cfg(test)]
mod tests {
    use crate::contract::{execute, execute_receive_cw20, execute_receive_nft, instantiate, query};
    use crate::msg::{ClaimMsg, ExecuteMsg, InstantiateMsg, PolicyResponse, QueryMsg};
    use crate::state::{InsurancePolicy, INSURANCE_POLICIES};

    use super::*;
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use cosmwasm_std::{coins, from_binary, to_binary};
    use cw20::Cw20ReceiveMsg;
    use cw721::Cw721ReceiveMsg;

    #[test]
    fn test_instantiate() {
        let mut deps = mock_dependencies();

        let msg = InstantiateMsg {
            cw20_token_address: "token0000".to_string(),
            cw721_contract_address: "nft0000".to_string(),
            treasury_address: "treasury0000".to_string(),
        };
        let info = mock_info("creator", &coins(1000, "earth"));

        let res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();
        assert_eq!(res.attributes.len(), 4);
        assert_eq!(res.attributes[0].value, "instantiate");
    }

    #[test]
    fn test_create_policy() {
        let mut deps = mock_dependencies();

        let instantiate_msg = InstantiateMsg {
            cw20_token_address: "token0000".to_string(),
            cw721_contract_address: "nft0000".to_string(),
            treasury_address: "treasury0000".to_string(),
        };
        let info = mock_info("creator", &coins(1000, "earth"));
        instantiate(deps.as_mut(), mock_env(), info.clone(), instantiate_msg).unwrap();

        let msg = ExecuteMsg::CreatePolicy {
            policy_id: "policy0001".to_string(),
            insured_amount: 1000,
            premium: 100,
            condition: "standard_condition".to_string(),
        };
        let info = mock_info("policy_holder", &[]);
        let res = execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();
        assert_eq!(res.attributes.len(), 5);
        assert_eq!(res.attributes[0].value, "execute_create_policy");

        let policy: InsurancePolicy = INSURANCE_POLICIES.load(&deps.storage, "policy0001").unwrap();
        assert_eq!(policy.policy_id, "policy0001");
        assert_eq!(policy.insured_amount, 1000);
        assert_eq!(policy.premium, 100);
        assert_eq!(policy.condition, "standard_condition");
        assert_eq!(policy.owner, info.sender);
        assert_eq!(policy.claimed, false);
    }

    #[test]
    fn test_pay_premium() {
        let mut deps = mock_dependencies();

        let instantiate_msg = InstantiateMsg {
            cw20_token_address: "token0000".to_string(),
            cw721_contract_address: "nft0000".to_string(),
            treasury_address: "treasury0000".to_string(),
        };
        let info = mock_info("creator", &coins(1000, "earth"));
        instantiate(deps.as_mut(), mock_env(), info.clone(), instantiate_msg).unwrap();

        let create_msg = ExecuteMsg::CreatePolicy {
            policy_id: "policy0001".to_string(),
            insured_amount: 1000,
            premium: 100,
            condition: "standard_condition".to_string(),
        };
        let info = mock_info("policy_holder", &[]);
        execute(deps.as_mut(), mock_env(), info.clone(), create_msg).unwrap();

        let pay_msg = ExecuteMsg::PayPremium {
            policy_id: "policy0001".to_string(),
            amount: 100,
        };
        let info = mock_info("policy_holder", &coins(100, "earth"));
        let res = execute(deps.as_mut(), mock_env(), info, pay_msg).unwrap();
        assert_eq!(res.attributes.len(), 4);
        assert_eq!(res.attributes[0].value, "execute_pay_premium");
    }

    #[test]
    fn test_claim_policy() {
        let mut deps = mock_dependencies();

        let instantiate_msg = InstantiateMsg {
            cw20_token_address: "token0000".to_string(),
            cw721_contract_address: "nft0000".to_string(),
            treasury_address: "treasury0000".to_string(),
        };
        let info = mock_info("creator", &coins(1000, "earth"));
        instantiate(deps.as_mut(), mock_env(), info.clone(), instantiate_msg).unwrap();

        let create_msg = ExecuteMsg::CreatePolicy {
            policy_id: "policy0001".to_string(),
            insured_amount: 1000,
            premium: 100,
            condition: "standard_condition".to_string(),
        };
        let info = mock_info("policy_holder", &[]);
        execute(deps.as_mut(), mock_env(), info.clone(), create_msg).unwrap();

        let claim_msg = ExecuteMsg::Claim {
            policy_id: "policy0001".to_string(),
        };
        let info = mock_info("policy_holder", &[]);
        let res = execute(deps.as_mut(), mock_env(), info, claim_msg).unwrap();
        assert_eq!(res.attributes.len(), 2);
        assert_eq!(res.attributes[0].value, "execute_claim");

        let policy: InsurancePolicy = INSURANCE_POLICIES.load(&deps.storage, "policy0001").unwrap();
        assert_eq!(policy.claimed, true);
    }

    #[test]
    fn test_receive_nft() {
        let mut deps = mock_dependencies();

        let instantiate_msg = InstantiateMsg {
            cw20_token_address: "token0000".to_string(),
            cw721_contract_address: "nft0000".to_string(),
            treasury_address: "treasury0000".to_string(),
        };
        let info = mock_info("creator", &coins(1000, "earth"));
        instantiate(deps.as_mut(), mock_env(), info.clone(), instantiate_msg).unwrap();

        let receive_nft_msg = Cw721ReceiveMsg {
            sender: "nft_holder".to_string(),
            token_id: "nft0001".to_string(),
            msg: to_binary(&"{}").unwrap(),
        };
        let info = mock_info("nft0000", &[]);
        let res = execute_receive_nft(deps.as_mut(), info, receive_nft_msg).unwrap();
        assert_eq!(res.attributes.len(), 2);
        assert_eq!(res.attributes[0].value, "execute_receive_nft");
    }

    #[test]
    fn test_query_policy() {
        let mut deps = mock_dependencies();

        let instantiate_msg = InstantiateMsg {
            cw20_token_address: "token0000".to_string(),
            cw721_contract_address: "nft0000".to_string(),
            treasury_address: "treasury0000".to_string(),
        };
        let info = mock_info("creator", &coins(1000, "earth"));
        instantiate(deps.as_mut(), mock_env(), info.clone(), instantiate_msg).unwrap();

        let create_msg = ExecuteMsg::CreatePolicy {
            policy_id: "policy0001".to_string(),
            insured_amount: 1000,
            premium: 100,
            condition: "standard_condition".to_string(),
        };
        let info = mock_info("policy_holder", &[]);
        execute(deps.as_mut(), mock_env(), info.clone(), create_msg).unwrap();

        let query_msg = QueryMsg::GetPolicy {
            policy_id: "policy0001".to_string(),
        };
        let res = query(deps.as_ref(), mock_env(), query_msg).unwrap();
        let policy_response: PolicyResponse = from_binary(&res).unwrap();

        assert_eq!(policy_response.policy_id, "policy0001");
        assert_eq!(policy_response.insured_amount, 1000);
        assert_eq!(policy_response.premium, 100);
        assert_eq!(policy_response.condition, "standard_condition");
    }
}
