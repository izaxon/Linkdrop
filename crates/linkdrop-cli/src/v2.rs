//! V2 (draft) mailbox commands: consecutive sends, window polling, acks, resends, rescue.
//!
//! State lives in `conversations.json` next to the V1 files, which stay untouched.

use std::{fs, path::Path};

use anyhow::{Context, Result, anyhow, bail};
use linkdrop_protocol::{
    ClientStateFile, DropRef, generate_contact_id, now_timestamp,
    v2::{
        ContactBundle, Conversation, DropStatus, Envelope, Incoming, MessageType, Outgoing,
        OwnedCapability, PollOutcome, WatchTarget,
    },
};
use serde::{Deserialize, Serialize};

use crate::{LinkdropApp, drop_ref_url};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConversationsFile {
    pub v: u8,
    #[serde(default)]
    pub conversations: Vec<Conversation>,
    #[serde(default)]
    pub pending_capabilities: Vec<OwnedCapability>,
    #[serde(default)]
    pub messages: Vec<V2MessageRecord>,
}

impl Default for ConversationsFile {
    fn default() -> Self {
        Self {
            v: 1,
            conversations: Vec::new(),
            pending_capabilities: Vec::new(),
            messages: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum V2Status {
    Sent,
    Delivered,
    Lost,
    Undeliverable,
    Received,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum V2Direction {
    Inbound,
    Outbound,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct V2MessageRecord {
    pub msg_id: String,
    pub contact_id: String,
    pub direction: V2Direction,
    pub created_at: i64,
    pub seq: u64,
    pub message_type: MessageType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    pub status: V2Status,
    pub resends: u32,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct V2PollSummary {
    pub received: usize,
    pub duplicates: usize,
    pub invalid: usize,
    pub missing: usize,
    pub delivered: usize,
    pub resent: usize,
    pub undeliverable: usize,
    pub new_contacts: usize,
    pub control_sent: usize,
}

impl LinkdropApp {
    /// Publish a V2 bundle with one fresh one-time capability per server.
    pub fn v2_export_bundle(&self, servers: &[String]) -> Result<ContactBundle> {
        let identity = self.whoami()?;
        let servers = self.v2_choose_servers(servers)?;
        let mut file = self.v2_read()?;
        let mut initial = Vec::with_capacity(servers.len());
        for server in &servers {
            let owned = OwnedCapability::generate(server);
            initial.push(owned.capability.clone());
            file.pending_capabilities.push(owned);
        }
        let bundle = ContactBundle {
            v: 2,
            display_name: Some(identity.display_name.clone()),
            identity_key: identity.tagged_identity_public_key(),
            initial,
        };
        bundle.validate(true)?;
        self.v2_write(&file)?;
        Ok(bundle)
    }

    /// Import a V2 bundle and prepare a conversation whose first send opens a chain.
    pub fn v2_import_bundle(&self, bundle_path: &Path) -> Result<Conversation> {
        let raw = fs::read_to_string(bundle_path)
            .with_context(|| format!("failed to read bundle file {}", bundle_path.display()))?;
        let bundle: ContactBundle =
            serde_json::from_str(&raw).context("failed to parse V2 contact bundle")?;
        bundle.validate(true)?;
        let servers = self.v2_choose_servers(&[])?;
        let mut file = self.v2_read()?;
        if file.conversations.iter().any(|conversation| {
            conversation.peer_identity_key.as_deref() == Some(&bundle.identity_key)
        }) {
            bail!("a V2 conversation with this identity already exists");
        }
        let conversation = Conversation::from_bundle(generate_contact_id(), &bundle, &servers)?;
        file.conversations.push(conversation.clone());
        self.v2_write(&file)?;
        Ok(conversation)
    }

    pub fn v2_list_conversations(&self) -> Result<Vec<Conversation>> {
        Ok(self.v2_read()?.conversations)
    }

    /// Send a text message. Consecutive calls never wait for the peer.
    pub fn v2_send(&self, contact_id: &str, text: &str) -> Result<V2MessageRecord> {
        if text.trim().is_empty() {
            bail!("message text must not be empty");
        }
        let signing_key = self.whoami()?.signing_key()?;
        let mut file = self.v2_read()?;
        let index = v2_find(&file, contact_id)?;
        let now = now_timestamp();

        let outgoing = file.conversations[index].prepare_text(&signing_key, text, now)?;
        let outgoing = self.v2_upload(&mut file.conversations[index], &signing_key, outgoing)?;
        let record = V2MessageRecord {
            msg_id: outgoing.content.msg_id.clone(),
            contact_id: contact_id.to_string(),
            direction: V2Direction::Outbound,
            created_at: now,
            seq: outgoing.content.seq,
            message_type: MessageType::Text,
            text: Some(text.to_string()),
            status: V2Status::Sent,
            resends: 0,
        };
        file.messages.push(record.clone());
        self.v2_write(&file)?;
        Ok(record)
    }

    /// Poll every watched drop, process messages in order, report gaps, resend what was lost.
    /// `wait_seconds` enables the optional long-poll extension on the lowest watched drop of
    /// each generation.
    pub fn v2_poll(&self, wait_seconds: Option<u64>) -> Result<V2PollSummary> {
        let identity = self.whoami()?;
        let signing_key = identity.signing_key()?;
        let servers = self.v2_choose_servers(&[])?;
        let mut file = self.v2_read()?;
        let mut summary = V2PollSummary::default();

        // New contacts writing to our bundle capabilities.
        let pending = file.pending_capabilities.clone();
        for capability in pending {
            let drop = DropRef {
                server: capability.capability.server.clone(),
                drop_id: capability.capability.drop_id.clone(),
            };
            let DropStatus::Present(envelope) = self.v2_fetch(&drop, None)? else {
                continue;
            };
            file.pending_capabilities
                .retain(|known| known.capability.drop_id != capability.capability.drop_id);
            match Conversation::from_capability_message(
                generate_contact_id(),
                &servers,
                &capability,
                &envelope,
            ) {
                Ok((conversation, incoming)) => {
                    let contact_id = conversation.contact_id.clone();
                    file.conversations.push(conversation);
                    summary.new_contacts += 1;
                    record_incoming(&mut file.messages, &contact_id, &incoming, &mut summary);
                }
                Err(_) => summary.invalid += 1,
            }
        }

        for index in 0..file.conversations.len() {
            let contact_id = file.conversations[index].contact_id.clone();
            let mut first_round = true;
            let mut conversation_missing = 0;
            loop {
                let targets = file.conversations[index].watch_targets();
                if targets.is_empty() {
                    break;
                }
                let mut results = Vec::with_capacity(targets.len());
                let mut lowest_seen = std::collections::HashSet::new();
                for target in targets {
                    let wait = match &target {
                        WatchTarget::Chain { generation, .. }
                            if first_round && lowest_seen.insert(*generation) =>
                        {
                            wait_seconds
                        }
                        _ => None,
                    };
                    let status = self.v2_fetch(target.drop(), wait)?;
                    results.push((target, status));
                }
                first_round = false;
                let outcome: PollOutcome = file.conversations[index].apply_poll(results)?;
                for incoming in &outcome.received {
                    record_incoming(&mut file.messages, &contact_id, incoming, &mut summary);
                }
                for msg_id in &outcome.delivered_msg_ids {
                    mark_outbound(&mut file.messages, &contact_id, msg_id, V2Status::Delivered);
                    summary.delivered += 1;
                }
                summary.invalid += outcome.invalid.len();
                summary.missing += outcome.newly_missing.len();
                conversation_missing += outcome.newly_missing.len();
                if !outcome.progressed {
                    break;
                }
            }

            // Expiry detection for our own unacknowledged drops.
            let unacked: Vec<_> = file.conversations[index]
                .unacknowledged()
                .iter()
                .map(|entry| (entry.msg_id.clone(), entry.drop.clone(), entry.needs_resend))
                .collect();
            for (msg_id, drop, needs_resend) in unacked {
                if needs_resend {
                    continue;
                }
                if self.v2_fetch(&drop, None)? == DropStatus::Absent {
                    file.conversations[index].mark_expired(&msg_id);
                    mark_outbound(&mut file.messages, &contact_id, &msg_id, V2Status::Lost);
                }
            }

            // Resend what the peer reported or what expired.
            let (queue, undeliverable) = file.conversations[index].take_resend_queue();
            for entry in undeliverable {
                mark_outbound(
                    &mut file.messages,
                    &contact_id,
                    &entry.msg_id,
                    V2Status::Undeliverable,
                );
                summary.undeliverable += 1;
            }
            for msg_id in queue {
                let now = now_timestamp();
                let outgoing =
                    file.conversations[index].prepare_resend(&signing_key, &msg_id, now)?;
                let outgoing =
                    self.v2_upload(&mut file.conversations[index], &signing_key, outgoing)?;
                if let Some(record) = file
                    .messages
                    .iter_mut()
                    .find(|record| record.contact_id == contact_id && record.msg_id == msg_id)
                {
                    record.status = V2Status::Sent;
                    record.seq = outgoing.content.seq;
                    record.resends += 1;
                }
                summary.resent += 1;
            }

            // Tell the peer about gaps even when we have nothing to say.
            if conversation_missing > 0 && file.conversations[index].send.target.is_some() {
                let now = now_timestamp();
                let outgoing = file.conversations[index].prepare_control(&signing_key, now)?;
                self.v2_upload(&mut file.conversations[index], &signing_key, outgoing)?;
                summary.control_sent += 1;
            }
        }

        self.v2_write(&file)?;
        Ok(summary)
    }

    pub fn v2_inbox(&self) -> Result<Vec<V2MessageRecord>> {
        let mut inbox: Vec<_> = self
            .v2_read()?
            .messages
            .into_iter()
            .filter(|record| record.direction == V2Direction::Inbound)
            .collect();
        inbox.sort_by_key(|record| record.created_at);
        Ok(inbox)
    }

    pub fn v2_history(&self, contact_id: &str) -> Result<Vec<V2MessageRecord>> {
        let mut history: Vec<_> = self
            .v2_read()?
            .messages
            .into_iter()
            .filter(|record| record.contact_id == contact_id)
            .collect();
        history.sort_by_key(|record| (record.created_at, record.seq));
        Ok(history)
    }

    /// Upload a prepared message, resolving `409` by comparison and recovering through a
    /// rescue capability when the chain turns out to be compromised.
    fn v2_upload(
        &self,
        conversation: &mut Conversation,
        signing_key: &ed25519_dalek::SigningKey,
        mut outgoing: Outgoing,
    ) -> Result<Outgoing> {
        for attempt in 0..2 {
            let body = serde_json::to_vec(&outgoing.envelope)?;
            let response = self
                .client
                .put(drop_ref_url(&outgoing.drop)?)
                .header("content-type", "application/json")
                .body(body.clone())
                .send()
                .with_context(|| format!("failed to send message to {}", outgoing.drop.server))?;
            match response.status().as_u16() {
                201 => {
                    conversation.commit_sent(&outgoing)?;
                    return Ok(outgoing);
                }
                409 => {
                    let stored = self
                        .client
                        .get(drop_ref_url(&outgoing.drop)?)
                        .send()
                        .with_context(|| format!("failed to read {}", outgoing.drop.server))?;
                    if stored.status().is_success() && stored.bytes()?.as_ref() == body.as_slice() {
                        conversation.commit_sent(&outgoing)?;
                        return Ok(outgoing);
                    }
                    if attempt == 1 || !conversation.mark_compromised() {
                        bail!(
                            "drop was taken by foreign bytes and no rescue capability is available; ask the peer for a new bundle"
                        );
                    }
                    outgoing = match outgoing.content.resend_of {
                        Some(_) => conversation.prepare_resend(
                            signing_key,
                            &outgoing.content.msg_id,
                            outgoing.content.created_at,
                        )?,
                        None => match outgoing.content.message_type {
                            MessageType::Text => conversation.prepare_text(
                                signing_key,
                                outgoing.content.text.as_deref().unwrap_or_default(),
                                outgoing.content.created_at,
                            )?,
                            MessageType::Control => conversation
                                .prepare_control(signing_key, outgoing.content.created_at)?,
                        },
                    };
                }
                400 => bail!("server rejected the envelope as invalid"),
                404 => bail!("drop endpoint was not found on the server"),
                413 => bail!("server rejected the envelope because it was too large"),
                code => bail!("unexpected server status {code}"),
            }
        }
        bail!("could not upload message after recovery")
    }

    fn v2_fetch(&self, drop: &DropRef, wait: Option<u64>) -> Result<DropStatus> {
        let mut url = drop_ref_url(drop)?;
        if let Some(seconds) = wait.filter(|seconds| *seconds > 0) {
            url.set_query(Some(&format!("wait={seconds}")));
        }
        let head = self
            .client
            .head(url.clone())
            .send()
            .with_context(|| format!("failed to poll {}", drop.server))?;
        match head.status().as_u16() {
            404 => return Ok(DropStatus::Absent),
            200 => {}
            _ => return Ok(DropStatus::Unknown),
        }
        url.set_query(None);
        let response = self
            .client
            .get(url)
            .send()
            .with_context(|| format!("failed to fetch {}", drop.server))?;
        match response.status().as_u16() {
            404 => Ok(DropStatus::Absent),
            200 => match response.json::<Envelope>() {
                Ok(envelope) if envelope.validate().is_ok() => Ok(DropStatus::Present(envelope)),
                _ => Ok(DropStatus::Unreadable),
            },
            _ => Ok(DropStatus::Unknown),
        }
    }

    fn v2_choose_servers(&self, servers: &[String]) -> Result<Vec<String>> {
        if !servers.is_empty() {
            let mut client_state =
                self.read_optional_json::<ClientStateFile>(&self.client_state_path())?;
            self.register_servers(&mut client_state, servers)?;
            self.write_json(&self.client_state_path(), &client_state)?;
            return Ok(servers.to_vec());
        }
        let client_state = self.read_optional_json::<ClientStateFile>(&self.client_state_path())?;
        if client_state.preferred_servers.is_empty() {
            bail!("at least one --server value is required, or add a preferred server first");
        }
        Ok(client_state.preferred_servers)
    }

    fn v2_read(&self) -> Result<ConversationsFile> {
        self.read_optional_json(&self.conversations_path())
    }

    fn v2_write(&self, file: &ConversationsFile) -> Result<()> {
        self.write_json(&self.conversations_path(), file)
    }

    fn conversations_path(&self) -> std::path::PathBuf {
        self.state_dir.join("conversations.json")
    }
}

fn v2_find(file: &ConversationsFile, contact_id: &str) -> Result<usize> {
    file.conversations
        .iter()
        .position(|conversation| conversation.contact_id == contact_id)
        .ok_or_else(|| anyhow!("V2 conversation {contact_id} not found"))
}

fn record_incoming(
    messages: &mut Vec<V2MessageRecord>,
    contact_id: &str,
    incoming: &Incoming,
    summary: &mut V2PollSummary,
) {
    if incoming.duplicate {
        summary.duplicates += 1;
        return;
    }
    if incoming.message_type == MessageType::Text {
        summary.received += 1;
    }
    messages.push(V2MessageRecord {
        msg_id: incoming.msg_id.clone(),
        contact_id: contact_id.to_string(),
        direction: V2Direction::Inbound,
        created_at: incoming.created_at,
        seq: incoming.seq,
        message_type: incoming.message_type,
        text: incoming.text.clone(),
        status: V2Status::Received,
        resends: 0,
    });
}

fn mark_outbound(
    messages: &mut [V2MessageRecord],
    contact_id: &str,
    msg_id: &str,
    status: V2Status,
) {
    if let Some(record) = messages.iter_mut().find(|record| {
        record.contact_id == contact_id
            && record.msg_id == msg_id
            && record.direction == V2Direction::Outbound
    }) {
        record.status = status;
    }
}

pub fn format_v2_conversations(conversations: &[Conversation]) -> String {
    if conversations.is_empty() {
        return "no V2 conversations".to_string();
    }
    conversations
        .iter()
        .map(|conversation| {
            format!(
                "{}\t{}\t{}\tsend_seq={}\trecv_seq={}\tunacked={}\tmissing={}",
                conversation.contact_id,
                conversation
                    .display_name
                    .clone()
                    .unwrap_or_else(|| "(unnamed)".to_string()),
                if conversation.verified {
                    "verified"
                } else {
                    "unverified"
                },
                conversation.send.next_seq,
                conversation.recv.next_seq,
                conversation.send.outbox.len(),
                conversation.recv.missing.len()
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn format_v2_messages(messages: &[V2MessageRecord], conversations: &[Conversation]) -> String {
    if messages.is_empty() {
        return "no messages".to_string();
    }
    messages
        .iter()
        .map(|record| {
            let name = conversations
                .iter()
                .find(|conversation| conversation.contact_id == record.contact_id)
                .and_then(|conversation| conversation.display_name.clone())
                .unwrap_or_else(|| record.contact_id.clone());
            format!(
                "{}\t{}\t{}\tseq={}\t{:?}\t{}",
                record.created_at,
                match record.direction {
                    V2Direction::Inbound => "<-",
                    V2Direction::Outbound => "->",
                },
                name,
                record.seq,
                record.status,
                record
                    .text
                    .clone()
                    .unwrap_or_else(|| "[control]".to_string())
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn format_v2_poll_summary(summary: &V2PollSummary) -> String {
    format!(
        "poll complete: received {}, duplicates {}, invalid {}, missing {}, delivered {}, resent {}, undeliverable {}, new contacts {}, control sent {}",
        summary.received,
        summary.duplicates,
        summary.invalid,
        summary.missing,
        summary.delivered,
        summary.resent,
        summary.undeliverable,
        summary.new_contacts,
        summary.control_sent
    )
}
