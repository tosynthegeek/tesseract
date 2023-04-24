#![cfg(test)]

use codec::Encode;
use ismp::{
    consensus::{IntermediateState, StateCommitment, StateMachineHeight, StateMachineId},
    host::StateMachine,
    messaging::CreateConsensusClient,
};
use ismp_parachain::consensus::PARACHAIN_CONSENSUS_ID;
use subxt::{
    config::{polkadot::PolkadotExtrinsicParams, substrate::SubstrateHeader, Hasher},
    ext::sp_core::keccak_256,
    utils::{AccountId32, MultiAddress, MultiSignature, H256},
};
use tesseract_parachain::{ParachainClient, ParachainConfig};

#[derive(Clone)]
pub struct Hyperbridge;

/// A type that can hash values using the blaks2_256 algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode)]
pub struct KeccakHasher;

impl Hasher for KeccakHasher {
    type Output = H256;
    fn hash(s: &[u8]) -> Self::Output {
        keccak_256(s).into()
    }
}

impl subxt::Config for Hyperbridge {
    type Index = u32;
    type Hash = H256;
    type AccountId = AccountId32;
    type Address = MultiAddress<Self::AccountId, u32>;
    type Signature = MultiSignature;
    type Hasher = KeccakHasher;
    type Header = SubstrateHeader<u32, KeccakHasher>;
    type ExtrinsicParams = PolkadotExtrinsicParams<Self>;
}

#[tokio::test]
async fn test_parachain_parachain_consensus_relay() -> Result<(), anyhow::Error> {
    env_logger::init();

    let config_a = ParachainConfig {
        state_machine: StateMachine::Kusama(2000),
        relay_chain: "ws://localhost:9944".to_string(),
        parachain: "ws://localhost:9988".to_string(),
        signer: "0xe5be9a5092b81bca64be81d212e7f2f9eba183bb7a90954f7b76361f6edb5c0a".to_string(),
    };
    let chain_a = ParachainClient::<Hyperbridge>::new(config_a).await?;

    let config_b = ParachainConfig {
        state_machine: StateMachine::Kusama(2001),
        relay_chain: "ws://localhost:9944".to_string(),
        parachain: "ws://localhost:9188".to_string(),
        signer: "0xe5be9a5092b81bca64be81d212e7f2f9eba183bb7a90954f7b76361f6edb5c0a".to_string(),
    };
    let chain_b = ParachainClient::<Hyperbridge>::new(config_b).await?;

    chain_a
        .create_consensus_client(CreateConsensusClient {
            consensus_state: vec![],
            consensus_client_id: PARACHAIN_CONSENSUS_ID,
            state_machine_commitments: vec![IntermediateState {
                height: StateMachineHeight {
                    id: StateMachineId {
                        state_id: chain_b.state_machine.clone(),
                        consensus_client: PARACHAIN_CONSENSUS_ID,
                    },
                    height: 0,
                },
                commitment: StateCommitment {
                    timestamp: 0,
                    ismp_root: None,
                    state_root: Default::default(),
                },
            }],
        })
        .await?;

    chain_b
        .create_consensus_client(CreateConsensusClient {
            consensus_state: vec![],
            consensus_client_id: PARACHAIN_CONSENSUS_ID,
            state_machine_commitments: vec![IntermediateState {
                height: StateMachineHeight {
                    id: StateMachineId {
                        state_id: chain_a.state_machine.clone(),
                        consensus_client: PARACHAIN_CONSENSUS_ID,
                    },
                    height: 0,
                },
                commitment: StateCommitment {
                    timestamp: 0,
                    ismp_root: None,
                    state_root: Default::default(),
                },
            }],
        })
        .await?;

    tesseract_consensus::relay(chain_a, chain_b).await?;

    Ok(())
}
