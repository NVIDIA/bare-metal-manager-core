/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use tokio::sync::mpsc;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ActorResult {
    Noop,
    Stop,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct AlarmId(u64);

#[derive(Debug, thiserror::Error)]
#[error("actor mailbox is closed")]
pub(crate) struct ActorMailboxClosed;

#[derive(Debug)]
enum MailboxCommand<Message> {
    Send(Message),
    SendAt {
        alarm_id: AlarmId,
        deadline: Instant,
        message: Message,
    },
    Cancel(AlarmId),
}

#[derive(Debug)]
pub(crate) struct ActorMailbox<Message> {
    tx: mpsc::UnboundedSender<MailboxCommand<Message>>,
    next_alarm_id: Arc<AtomicU64>,
    cancelled_alarms: Arc<Mutex<HashSet<AlarmId>>>,
}

impl<Message> Clone for ActorMailbox<Message> {
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
            next_alarm_id: self.next_alarm_id.clone(),
            cancelled_alarms: self.cancelled_alarms.clone(),
        }
    }
}

impl<Message> ActorMailbox<Message> {
    pub(crate) fn send(&self, message: Message) -> Result<(), ActorMailboxClosed> {
        self.tx
            .send(MailboxCommand::Send(message))
            .map_err(|_| ActorMailboxClosed)
    }

    pub(crate) fn send_at(
        &self,
        deadline: Instant,
        message: Message,
    ) -> Result<AlarmId, ActorMailboxClosed> {
        // `fetch_add` wraps on overflow, but exhausting the u64 ID space during one actor's
        // lifetime is not realistic.
        let alarm_id = AlarmId(self.next_alarm_id.fetch_add(1, Ordering::Relaxed));
        self.tx
            .send(MailboxCommand::SendAt {
                alarm_id,
                deadline,
                message,
            })
            .map_err(|_| ActorMailboxClosed)?;
        Ok(alarm_id)
    }

    pub(crate) fn cancel(&self, alarm_id: AlarmId) {
        self.cancelled_alarms
            .lock()
            .expect("cancelled alarms lock must not be poisoned")
            .insert(alarm_id);
        self.tx.send(MailboxCommand::Cancel(alarm_id)).ok();
    }

    pub(crate) fn replace_alarm(
        &self,
        alarm_id: Option<AlarmId>,
        deadline: Instant,
        message: Message,
    ) -> Result<AlarmId, ActorMailboxClosed> {
        if let Some(alarm_id) = alarm_id {
            self.cancel(alarm_id);
        }
        self.send_at(deadline, message)
    }
}

pub(crate) trait ActorCallbacks<Message> {
    async fn message(&mut self, mailbox: &ActorMailbox<Message>, message: Message) -> ActorResult;
}

pub(crate) struct Actor<State, Message> {
    state: State,
    mailbox: ActorMailbox<Message>,
    mailbox_rx: mpsc::UnboundedReceiver<MailboxCommand<Message>>,
    alarms: BinaryHeap<Reverse<(Instant, AlarmId)>>,
    alarm_messages: HashMap<AlarmId, Message>,
    cancelled_alarms: Arc<Mutex<HashSet<AlarmId>>>,
}

impl<State, Message> Actor<State, Message>
where
    State: ActorCallbacks<Message>,
{
    pub(crate) fn new(state: State, initial_message: Message) -> (Self, ActorMailbox<Message>) {
        let (tx, mailbox_rx) = mpsc::unbounded_channel();
        let cancelled_alarms = Arc::new(Mutex::new(HashSet::new()));
        let mailbox = ActorMailbox {
            tx,
            next_alarm_id: Arc::new(AtomicU64::new(0)),
            cancelled_alarms: cancelled_alarms.clone(),
        };
        mailbox
            .send(initial_message)
            .expect("new actor mailbox must be open");
        (
            Self {
                state,
                mailbox: mailbox.clone(),
                mailbox_rx,
                alarms: BinaryHeap::new(),
                alarm_messages: HashMap::new(),
                cancelled_alarms,
            },
            mailbox,
        )
    }

    pub(crate) async fn run(mut self) {
        loop {
            while self
                .alarms
                .peek()
                .is_some_and(|Reverse((_, alarm_id))| !self.alarm_messages.contains_key(alarm_id))
            {
                self.alarms.pop();
            }
            let next_deadline = self.alarms.peek().map(|Reverse((deadline, _))| *deadline);
            let input = if let Some(deadline) = next_deadline {
                tokio::select! {
                    _ = tokio::time::sleep_until(deadline.into()) => ActorInput::Alarm,
                    command = self.mailbox_rx.recv() => ActorInput::Command(command),
                }
            } else {
                ActorInput::Command(self.mailbox_rx.recv().await)
            };

            let message = match input {
                ActorInput::Alarm => {
                    let Some(Reverse((_, alarm_id))) = self.alarms.pop() else {
                        continue;
                    };
                    let Some(message) = self.alarm_messages.remove(&alarm_id) else {
                        continue;
                    };
                    if self
                        .cancelled_alarms
                        .lock()
                        .expect("cancelled alarms lock must not be poisoned")
                        .remove(&alarm_id)
                    {
                        continue;
                    }
                    message
                }
                ActorInput::Command(Some(MailboxCommand::Send(message))) => message,
                ActorInput::Command(Some(MailboxCommand::SendAt {
                    alarm_id,
                    deadline,
                    message,
                })) => {
                    self.alarms.push(Reverse((deadline, alarm_id)));
                    self.alarm_messages.insert(alarm_id, message);
                    continue;
                }
                ActorInput::Command(Some(MailboxCommand::Cancel(alarm_id))) => {
                    self.alarm_messages.remove(&alarm_id);
                    self.cancelled_alarms
                        .lock()
                        .expect("cancelled alarms lock must not be poisoned")
                        .remove(&alarm_id);
                    continue;
                }
                ActorInput::Command(None) => break,
            };

            if self.state.message(&self.mailbox, message).await == ActorResult::Stop {
                break;
            }
        }
    }
}

enum ActorInput<Message> {
    Alarm,
    Command(Option<MailboxCommand<Message>>),
}
