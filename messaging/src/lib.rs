// Copyright (C) Polytope Labs Ltd.
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

//! ISMP Message relay

mod event_parser;

use crate::event_parser::{filter_events, parse_ismp_events};
use futures::StreamExt;
use ismp::consensus::StateMachineHeight;
use tesseract_primitives::{config::RelayerConfig, IsmpHost, IsmpProvider};

pub async fn relay<A, B>(
    chain_a: A,
    chain_b: B,
    _config: Option<RelayerConfig>,
) -> Result<(), anyhow::Error>
where
    A: IsmpHost + IsmpProvider,
    B: IsmpHost + IsmpProvider,
{
    log::info!(target: "tesseract", "🛰️ Starting messaging relay");
    let mut state_machine_update_stream_a =
        chain_a.state_machine_update_notification(chain_b.state_machine_id()).await;
    let mut state_machine_update_stream_b =
        chain_b.state_machine_update_notification(chain_a.state_machine_id()).await;

    loop {
        tokio::select! {
            result = state_machine_update_stream_a.next() =>  {
                match result {
                    None => break,
                    Some(Ok(state_machine_update)) => {
                        // Chain B's state machine has been updated to a new height on chain A
                        // We query all the events that have been emitted on chain B that can be submitted to chain A
                        // filter events list to contain only Request and Response events
                        let events = chain_b.query_ismp_events(state_machine_update).await?.into_iter()
                            .filter(|ev| filter_events(chain_a.state_machine_id().state_id, ev)).collect::<Vec<_>>();

                        if events.is_empty() {
                            continue
                        }
                        log::info!(
                            target: "tesseract",
                            "Events from {} {:?}", chain_b.name(),
                            events // event names
                         );
                        let state_machine_height = StateMachineHeight {
                            id: state_machine_update.state_machine_id,
                            height: state_machine_update.latest_height
                        };
                        let (messages, get_responses) = parse_ismp_events(&chain_b, &chain_a, events, state_machine_height).await?;

                        if !messages.is_empty() {
                            log::info!(
                                target: "tesseract",
                                "🛰️Submitting ismp messages from {} to {}",
                                chain_b.name(), chain_a.name()
                            );
                            chain_a.submit(messages).await?;
                        }

                        if !get_responses.is_empty() {
                            log::info!(
                                target: "tesseract",
                                "🛰️Submitting GET response messages to {}",
                                chain_b.name()
                            );
                            chain_b.submit(get_responses).await?;
                        }
                    },
                    Some(Err(e)) => {
                        log::error!(
                            target: "tesseract",
                            "{} encountered an error in the state machine update notification stream: {e}", chain_a.name()
                        )
                    }
                }
            }

            result = state_machine_update_stream_b.next() =>  {
                 match result {
                    None => break,
                    Some(Ok(state_machine_update)) => {
                        // Chain A's state machine has been updated to a new height on chain B
                        // We query all the events that have been emitted on chain A that can be submitted to chain B

                        // filter events list to contain only Request and Response events
                        let events = chain_a.query_ismp_events(state_machine_update).await?.into_iter()
                            .filter(|ev| filter_events(chain_b.state_machine_id().state_id, ev)).collect::<Vec<_>>();
                        if events.is_empty() {
                            continue
                        }
                        log::info!(
                            target: "tesseract",
                            "Events from {} {:?}", chain_a.name(),
                            events
                         );
                        let state_machine_height = StateMachineHeight {
                            id: state_machine_update.state_machine_id,
                            height: state_machine_update.latest_height
                        };
                        let (messages, get_responses) = parse_ismp_events(&chain_a, &chain_b, events, state_machine_height).await?;
                        if !messages.is_empty() {
                            log::info!(
                                target: "tesseract",
                                "🛰️Submitting ismp messages from {} to {}",
                                chain_a.name(), chain_b.name()
                            );
                            chain_b.submit(messages).await?;
                        }

                        if !get_responses.is_empty() {
                            log::info!(
                                target: "tesseract",
                                "🛰️Submitting GET response messages to {}",
                                chain_a.name()
                            );
                            chain_a.submit(get_responses).await?;
                        }
                    },
                    Some(Err(e)) => {
                        log::error!(
                            target: "tesseract",
                            "{} encountered an error in the state machine update notification stream: {e}", chain_b.name()
                        )
                    }
                }
            }
        }
    }

    Ok(())
}
