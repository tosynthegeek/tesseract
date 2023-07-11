// Copyright (C) 2023 Polytope Labs.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! [`IsmpProvider`] implementation

use crate::{
    extrinsic::{send_extrinsic, Extrinsic, InMemorySigner},
    SubstrateClient,
};
use codec::{Decode, Encode};
use futures::stream::StreamExt;
use ismp::{
    consensus::{ConsensusClientId, StateMachineId},
    router::{Get, Request, Response},
};
use ismp_parachain::consensus::{MembershipProof, SubstrateStateProof};
use ismp_primitives::LeafIndexQuery;
use ismp_rpc::BlockNumberOrHash;
use pallet_ismp::{primitives::Proof as MmrProof, NodesUtils};
use primitives::{BoxStream, IsmpProvider, Query, StateMachineUpdated};
use sp_core::{sp_std::sync::Arc, Pair, H256};
use std::{collections::HashMap, time::Duration};
use subxt::{
    config::{
        extrinsic_params::BaseExtrinsicParamsBuilder, polkadot::PlainTip, ExtrinsicParams, Header,
    },
    events::EventDetails,
    ext::sp_runtime::{traits::IdentifyAccount, MultiSignature, MultiSigner},
    rpc_params,
};

#[async_trait::async_trait]
impl<T, C> IsmpProvider for SubstrateClient<T, C>
where
    C: subxt::Config + Send + Sync,
    C::Header: Send + Sync,
    <C::ExtrinsicParams as ExtrinsicParams<C::Index, C::Hash>>::OtherParams:
        Default + Send + From<BaseExtrinsicParamsBuilder<C, PlainTip>>,
    C::AccountId:
        From<sp_core::crypto::AccountId32> + Into<C::Address> + Clone + 'static + Send + Sync,
    C::Signature: From<MultiSignature> + Send + Sync,
    T: Send + Sync,
{
    async fn query_consensus_state(
        &self,
        at: Option<u64>,
        id: ConsensusClientId,
    ) -> Result<Vec<u8>, anyhow::Error> {
        let params = rpc_params![at, id];
        let response = self.client.rpc().request("ismp_queryConsensusState", params).await?;

        Ok(response)
    }

    async fn query_latest_state_machine_height(
        &self,
        id: StateMachineId,
    ) -> Result<u32, anyhow::Error> {
        let params = rpc_params![id];
        let response =
            self.client.rpc().request("ismp_queryStateMachineLatestHeight", params).await?;

        Ok(response)
    }

    async fn query_consensus_update_time(
        &self,
        id: ConsensusClientId,
    ) -> Result<Duration, anyhow::Error> {
        let params = rpc_params![id];
        let response: u64 =
            self.client.rpc().request("ismp_queryConsensusUpdateTime", params).await?;

        Ok(Duration::from_secs(response))
    }

    async fn query_requests_proof(
        &self,
        at: u64,
        keys: Vec<Query>,
    ) -> Result<Vec<u8>, anyhow::Error> {
        let params = rpc_params![at, convert_queries(keys)];
        let response: ismp_rpc::Proof =
            self.client.rpc().request("ismp_queryRequestsMmrProof", params).await?;
        let mmr_proof: MmrProof<H256> = Decode::decode(&mut &*response.proof)?;
        let proof = MembershipProof {
            mmr_size: NodesUtils::new(mmr_proof.leaf_count).size(),
            leaf_indices: mmr_proof.leaf_indices,
            proof: mmr_proof.items,
        };
        Ok(proof.encode())
    }

    async fn query_responses_proof(
        &self,
        at: u64,
        keys: Vec<Query>,
    ) -> Result<Vec<u8>, anyhow::Error> {
        let params = rpc_params![at, convert_queries(keys)];
        let response: ismp_rpc::Proof =
            self.client.rpc().request("ismp_queryResponsesMmrProof", params).await?;
        let mmr_proof: MmrProof<H256> = Decode::decode(&mut &*response.proof)?;
        let proof = MembershipProof {
            mmr_size: NodesUtils::new(mmr_proof.leaf_count).size(),
            leaf_indices: mmr_proof.leaf_indices,
            proof: mmr_proof.items,
        };
        Ok(proof.encode())
    }

    async fn query_state_proof(
        &self,
        at: u64,
        keys: Vec<Vec<u8>>,
    ) -> Result<Vec<u8>, anyhow::Error> {
        let params = rpc_params![at, keys];
        let response: ismp_rpc::Proof =
            self.client.rpc().request("ismp_queryStateProof", params).await?;

        let storage_proof: Vec<Vec<u8>> = Decode::decode(&mut &*response.proof)?;
        let proof = SubstrateStateProof { hasher: self.hashing.clone(), storage_proof };

        Ok(proof.encode())
    }

    async fn query_ismp_events(
        &self,
        event: StateMachineUpdated,
    ) -> Result<Vec<pallet_ismp::events::Event>, anyhow::Error> {
        let latest_state_machine_height = Arc::clone(&self.latest_state_machine_height);

        let block_numbers: Vec<BlockNumberOrHash<sp_core::H256>> =
            ((*latest_state_machine_height.lock() + 1)..=event.latest_height)
                .into_iter()
                .map(|block_height| BlockNumberOrHash::Number(block_height as u32))
                .collect();
        *latest_state_machine_height.lock() = event.latest_height;

        let params = rpc_params![block_numbers];
        let response: HashMap<String, Vec<pallet_ismp::events::Event>> =
            self.client.rpc().request("ismp_queryEvents", params).await?;

        Ok(response.values().into_iter().cloned().flatten().collect())
    }

    async fn query_requests(&self, keys: Vec<Query>) -> Result<Vec<Request>, anyhow::Error> {
        let queries = convert_queries(keys);
        let params = rpc_params![queries];
        let response = self.client.rpc().request("ismp_queryRequests", params).await?;

        Ok(response)
    }

    async fn query_responses(&self, keys: Vec<Query>) -> Result<Vec<Response>, anyhow::Error> {
        let queries = convert_queries(keys);
        let params = rpc_params![queries];
        let response = self.client.rpc().request("ismp_queryResponses", params).await?;

        Ok(response)
    }

    async fn query_pending_get_requests(&self, height: u64) -> Result<Vec<Get>, anyhow::Error> {
        let response =
            self.client.rpc().request("ismp_pendingGetRequests", rpc_params![height]).await?;
        Ok(response)
    }

    fn name(&self) -> String {
        self.state_machine.to_string()
    }

    fn state_machine_id(&self) -> StateMachineId {
        StateMachineId { state_id: self.state_machine, consensus_client: self.consensus_client }
    }

    fn block_max_gas(&self) -> u64 {
        todo!()
    }

    async fn estimate_gas(
        &self,
        _msg: Vec<ismp::messaging::Message>,
    ) -> Result<u64, anyhow::Error> {
        todo!()
    }

    async fn state_machine_update_notification(
        &self,
        counterparty_state_id: StateMachineId,
    ) -> BoxStream<StateMachineUpdated> {
        let client = self.client.clone();

        let subscription = self
            .client
            .rpc()
            .subscribe_best_block_headers()
            .await
            .expect("Failed to get best block stream");

        let stream = subscription.filter_map(move |header| {
            let client = client.clone();
            async move {
                let events = client.events().at(header.ok()?.hash()).await.ok()?;

                let event = events
                    .iter()
                    .filter_map(|ev| {
                        let ev = ev.ok()?;
                        decode_state_machine_update_event(ev).transpose()
                    })
                    .find(|ev| match ev {
                        Ok(StateMachineUpdated { state_machine_id, .. }) => {
                            state_machine_id == &counterparty_state_id
                        }
                        _ => false,
                    });
                event
            }
        });

        Box::pin(stream)
    }

    async fn submit(&self, messages: Vec<ismp::messaging::Message>) -> Result<(), anyhow::Error> {
        let signer = InMemorySigner {
            account_id: MultiSigner::Sr25519(self.signer.public()).into_account().into(),
            signer: self.signer.clone(),
        };

        let call = messages.encode();
        let tx = Extrinsic::new("Ismp", "handle", call);
        let progress = send_extrinsic(&self.client, signer, tx).await?;
        let tx = progress.wait_for_in_block().await?;
        tx.wait_for_success().await?;

        Ok(())
    }
}

fn decode_state_machine_update_event<T: subxt::Config>(
    ev: EventDetails<T>,
) -> Result<Option<StateMachineUpdated>, anyhow::Error> {
    let ev_metadata = ev.event_metadata();
    if ev_metadata.pallet.name() == "Ismp" && ev_metadata.variant.name == "StateMachineUpdated" {
        let bytes = ev.field_bytes();
        let event: StateMachineUpdated = codec::Decode::decode(&mut &*bytes)?;
        Ok(Some(event))
    } else {
        Ok(None)
    }
}

fn convert_queries(queries: Vec<Query>) -> Vec<LeafIndexQuery> {
    queries
        .into_iter()
        .map(|query| LeafIndexQuery {
            source_chain: query.source_chain,
            dest_chain: query.dest_chain,
            nonce: query.nonce,
        })
        .collect()
}
