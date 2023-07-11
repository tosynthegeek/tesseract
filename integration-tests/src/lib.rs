#![cfg(test)]

use codec::Encode;
use ismp::host::StateMachine;

use ismp_demo::GetRequest;
use ismp_parachain::consensus::HashAlgorithm;
use sp_io::hashing::blake2_256;
use std::{future::Future, time::Duration};
use substrate_common::{SubstrateClient, SubstrateConfig};
use subxt::{
    config::{polkadot::PolkadotExtrinsicParams, substrate::SubstrateHeader, Hasher},
    utils::{AccountId32, MultiAddress, MultiSignature, H256},
};

use tesseract_parachain::{ParachainConfig, ParachainHost};

type ParachainClient<T> = SubstrateClient<ParachainHost<T>, T>;

#[derive(Clone)]
pub struct Hyperbridge;

/// A type that can hash values using the keccak_256 algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode)]
pub struct RuntimeHasher;

impl Hasher for RuntimeHasher {
    type Output = H256;
    fn hash(s: &[u8]) -> Self::Output {
        blake2_256(s).into()
    }
}

impl subxt::Config for Hyperbridge {
    type Index = u32;
    type Hash = H256;
    type AccountId = AccountId32;
    type Address = MultiAddress<Self::AccountId, u32>;
    type Signature = MultiSignature;
    type Hasher = RuntimeHasher;
    type Header = SubstrateHeader<u32, RuntimeHasher>;
    type ExtrinsicParams = PolkadotExtrinsicParams<Self>;
}

async fn setup_clients(
) -> Result<(ParachainClient<Hyperbridge>, ParachainClient<Hyperbridge>), anyhow::Error> {
    let config_a = ParachainConfig {
        relay_chain: "ws://localhost:9944".to_string(),

        substrate: SubstrateConfig {
            state_machine: StateMachine::Kusama(2000),
            hashing: HashAlgorithm::Blake2,
            consensus_client: "PARA".to_string(),
            ws_url: "ws://localhost:9988".to_string(),
            signer: "0xe5be9a5092b81bca64be81d212e7f2f9eba183bb7a90954f7b76361f6edb5c0a"
                .to_string(),
            latest_state_machine_height: None,
        },
    };
    let host_a = ParachainHost::<Hyperbridge>::new(&config_a).await?;
    let chain_a = SubstrateClient::new(host_a, config_a.substrate).await?;

    let config_b = ParachainConfig {
        relay_chain: "ws://localhost:9944".to_string(),
        substrate: SubstrateConfig {
            state_machine: StateMachine::Kusama(2001),
            hashing: HashAlgorithm::Blake2,
            consensus_client: "PARA".to_string(),
            ws_url: "ws://localhost:9188".to_string(),
            signer: "0xe5be9a5092b81bca64be81d212e7f2f9eba183bb7a90954f7b76361f6edb5c0a"
                .to_string(),
            latest_state_machine_height: None,
        },
    };
    let host_b = ParachainHost::<Hyperbridge>::new(&config_b).await?;
    let chain_b = SubstrateClient::new(host_b, config_b.substrate).await?;
    Ok((chain_a, chain_b))
}

pub fn setup_logging() {
    use log::LevelFilter;
    env_logger::builder()
        .filter_module("tesseract", LevelFilter::Info)
        .format_module_path(false)
        .init();
}

pub async fn timeout_future<T: Future>(future: T, secs: u64, reason: String) -> T::Output {
    let duration = Duration::from_secs(secs);
    match tokio::time::timeout(duration.clone(), future).await {
        Ok(output) => output,
        Err(_) => panic!("Future didn't finish within {duration:?}, {reason}"),
    }
}

async fn transfer_assets(
    chain_a: &ParachainClient<Hyperbridge>,
    chain_b: &ParachainClient<Hyperbridge>,
) -> Result<(), anyhow::Error> {
    let amt = 345876451382054092;

    let params =
        ismp_demo::TransferParams { to: chain_b.account(), amount: amt, timeout: 0, para_id: 2001 };
    dbg!(amt);
    chain_a.transfer(params).await?;

    timeout_future(
        chain_b.ismp_demo_events_stream(1, "IsmpDemo", "BalanceReceived"),
        60 * 4,
        "Did not see BalanceReceived Event".to_string(),
    )
    .await?;

    dbg!(amt);
    let params_b =
        ismp_demo::TransferParams { to: chain_a.account(), amount: amt, timeout: 0, para_id: 2000 };

    chain_b.transfer(params_b).await?;

    timeout_future(
        chain_a.ismp_demo_events_stream(1, "IsmpDemo", "BalanceReceived"),
        60 * 4,
        "Did not see BalanceReceived Event".to_string(),
    )
    .await?;
    Ok(())
}

#[tokio::test]
async fn test_parachain_parachain_messaging_relay() -> Result<(), anyhow::Error> {
    setup_logging();

    let (chain_a, chain_b) = setup_clients().await?;

    // Change signer for messaging process to avoid transaction priority errors
    // chain_a.signer = sp_keyring::AccountKeyring::Bob.pair();
    // chain_b.signer = sp_keyring::AccountKeyring::Bob.pair();

    let _message_handle = tokio::spawn({
        let chain_a = chain_a.clone();
        let chain_b = chain_b.clone();
        async move { tesseract_messaging::relay(chain_a.clone(), chain_b.clone(), None).await.unwrap() }
    });

    // Make transfers each from both chains
    transfer_assets(&chain_a, &chain_b).await?;

    // Send a Get request next
    chain_a
        .get_request(GetRequest {
            para_id: 2001,
            height: chain_b.latest_state_machine_height() as u32,
            timeout: 0,
            keys: vec![hex::decode(
                "c2261276cc9d1f8598ea4b6a74b15c2f57c875e4cff74148e4628f264b974c80".to_string(),
            )
            .unwrap()],
        })
        .await?;

    timeout_future(
        chain_a.ismp_demo_events_stream(1, "IsmpDemo", "GetResponse"),
        60 * 4,
        "Did not see Get Response Event".to_string(),
    )
    .await?;

    Ok(())
}

#[ignore]
#[tokio::test]
async fn test_messaging_relay() -> Result<(), anyhow::Error> {
    setup_logging();

    let (chain_a, chain_b) = setup_clients().await?;

    // Change signer for messaging process to avoid transaction priority errors
    // chain_a.signer = sp_keyring::AccountKeyring::Bob.pair();
    // chain_b.signer = sp_keyring::AccountKeyring::Bob.pair();

    let message_handle = tokio::spawn({
        let chain_a = chain_a.clone();
        let chain_b = chain_b.clone();
        async move { tesseract_messaging::relay(chain_a.clone(), chain_b.clone(), None).await.unwrap() }
    });

    message_handle.await.unwrap();

    Ok(())
}
