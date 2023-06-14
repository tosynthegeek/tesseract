#![cfg(test)]

use codec::Encode;
use ismp::host::StateMachine;

use ismp_demo::GetRequest;
use std::{future::Future, time::Duration};
use subxt::{
    config::{
        polkadot::PolkadotExtrinsicParams,
        substrate::{BlakeTwo256, SubstrateHeader},
        Hasher,
    },
    ext::sp_core::keccak_256,
    utils::{AccountId32, MultiAddress, MultiSignature, H256},
};
use tesseract_parachain::{parachain, ParachainClient, ParachainConfig};

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

async fn setup_clients(
) -> Result<(ParachainClient<Hyperbridge>, ParachainClient<Hyperbridge>), anyhow::Error> {
    let config_a = ParachainConfig {
        state_machine: StateMachine::Kusama(2000),
        relay_chain: "ws://localhost:9944".to_string(),
        parachain: "ws://localhost:9988".to_string(),
        signer: "0xe5be9a5092b81bca64be81d212e7f2f9eba183bb7a90954f7b76361f6edb5c0a".to_string(),
        latest_state_machine_height: None,
    };
    let chain_a = ParachainClient::<Hyperbridge>::new(config_a).await?;

    let config_b = ParachainConfig {
        state_machine: StateMachine::Kusama(2001),
        relay_chain: "ws://localhost:9944".to_string(),
        parachain: "ws://localhost:9188".to_string(),
        signer: "0xe5be9a5092b81bca64be81d212e7f2f9eba183bb7a90954f7b76361f6edb5c0a".to_string(),
        latest_state_machine_height: None,
    };
    let chain_b = ParachainClient::<Hyperbridge>::new(config_b).await?;
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
    let amt = (30 * chain_a.balance().await?) / 100;

    let params =
        ismp_demo::TransferParams { to: chain_b.account(), amount: amt, timeout: 0, para_id: 2001 };
    dbg!(amt);
    chain_a.transfer(params).await?;

    timeout_future(
        chain_b.ismp_demo_events_stream::<parachain::api::ismp_demo::events::BalanceReceived>(1),
        60 * 4,
        "Did not see BalanceReceived Event".to_string(),
    )
    .await?;
    let amt = (30 * chain_b.balance().await?) / 100;
    dbg!(amt);
    let params_b =
        ismp_demo::TransferParams { to: chain_a.account(), amount: amt, timeout: 0, para_id: 2000 };

    chain_b.transfer(params_b).await?;

    timeout_future(
        chain_a.ismp_demo_events_stream::<parachain::api::ismp_demo::events::BalanceReceived>(1),
        60 * 4,
        "Did not see BalanceReceived Event".to_string(),
    )
    .await?;
    Ok(())
}

#[tokio::test]
async fn test_parachain_parachain_messaging_relay() -> Result<(), anyhow::Error> {
    setup_logging();

    let (mut chain_a, mut chain_b) = setup_clients().await?;

    // Change signer for messaging process to avoid transaction priority errors
    chain_a.signer = sp_keyring::AccountKeyring::Bob.pair();
    chain_b.signer = sp_keyring::AccountKeyring::Bob.pair();

    let _message_handle = tokio::spawn({
        let chain_a = chain_a.clone();
        let chain_b = chain_b.clone();
        async move { tesseract_message::relay(chain_a.clone(), chain_b.clone()).await.unwrap() }
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
        chain_a.ismp_demo_events_stream::<parachain::api::ismp_demo::events::GetResponse>(1),
        60 * 4,
        "Did not see Get Response Event".to_string(),
    )
    .await?;

    Ok(())
}

#[tokio::test]
async fn test_messaging_relay() -> Result<(), anyhow::Error> {
    setup_logging();

    let (mut chain_a, mut chain_b) = setup_clients().await?;

    // Change signer for messaging process to avoid transaction priority errors
    chain_a.signer = sp_keyring::AccountKeyring::Bob.pair();
    chain_b.signer = sp_keyring::AccountKeyring::Bob.pair();

    let message_handle = tokio::spawn({
        let chain_a = chain_a.clone();
        let chain_b = chain_b.clone();
        async move { tesseract_message::relay(chain_a.clone(), chain_b.clone()).await.unwrap() }
    });

    message_handle.await.unwrap();

    Ok(())
}
