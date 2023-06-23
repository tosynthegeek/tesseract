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

use crate::ParachainClient;
use anyhow::anyhow;
use ismp::messaging::ConsensusMessage;
use tesseract_primitives::{ByzantineHandler, ChallengePeriodStarted, IsmpHost};

#[async_trait::async_trait]
impl<T> ByzantineHandler for ParachainClient<T>
where
    T: subxt::Config,
{
    async fn query_consensus_message(
        &self,
        _challenge_event: ChallengePeriodStarted,
    ) -> Result<ConsensusMessage, anyhow::Error> {
        Err(anyhow!("Parachains consensus can't misbehave"))?
    }

    async fn check_for_byzantine_attack<C: IsmpHost>(
        &self,
        _counterparty: &C,
        _consensus_message: ConsensusMessage,
    ) -> Result<(), anyhow::Error> {
        Err(anyhow!("Parachains consensus can't misbehave"))?
    }
}
