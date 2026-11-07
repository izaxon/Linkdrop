//! Per-contact V2 conversation state machine (spec §4 and §6). No I/O: callers fetch and
//! upload drops and feed results back in.

use ed25519_dalek::SigningKey;
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::{
    crypto::x25519_secret_key,
    decode_base64url, encode_base64url,
    encoding::tagged_base64,
    error::{ProtocolError, Result},
    model::DropRef,
    v2::{
        chain::{chain_drop, derive_chain_key},
        crypto::{open, seal},
        model::{
            ContactBundle, DropCapability, Envelope, MessageType, PayloadContent, ReceiveProfile,
        },
    },
};

/// Reference window size (spec §4.3).
pub const DEFAULT_WINDOW: u64 = 8;
/// Reference resend cap (spec §6.3).
pub const MAX_RESENDS: u32 = 3;
const MAX_SEEN_MSG_IDS: usize = 512;
const MAX_PEER_RESCUES: usize = 2;

/// One generation we receive on, with its secrets.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OwnedGeneration {
    #[serde(rename = "gen")]
    pub generation: u64,
    pub chain_key: String,
    pub receive_secret: String,
    pub receive_key: String,
    pub servers: Vec<String>,
    pub adopted: bool,
}

impl OwnedGeneration {
    pub fn profile(&self) -> ReceiveProfile {
        ReceiveProfile {
            generation: self.generation,
            chain_key: self.chain_key.clone(),
            receive_key: self.receive_key.clone(),
            servers: self.servers.clone(),
        }
    }

    fn secret(&self) -> Result<StaticSecret> {
        x25519_secret_key(&self.receive_secret)
    }
}

/// A one-time capability we own, with its secret.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OwnedCapability {
    pub capability: DropCapability,
    pub secret: String,
}

impl OwnedCapability {
    pub fn generate(server: &str) -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        let mut drop_id = [0_u8; 32];
        OsRng.fill_bytes(&mut drop_id);
        Self {
            capability: DropCapability {
                server: server.to_string(),
                drop_id: encode_base64url(&drop_id),
                recipient_key: tagged_base64("x25519", public.as_bytes()),
            },
            secret: encode_base64url(&secret.to_bytes()),
        }
    }

    pub fn secret_key(&self) -> Result<StaticSecret> {
        x25519_secret_key(&self.secret)
    }
}

/// Where the next outgoing message goes.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SendTarget {
    Capability { capability: DropCapability },
    Chain { profile: ReceiveProfile },
}

/// A written message that has not been acknowledged.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OutboxEntry {
    pub msg_id: String,
    pub original_seq: u64,
    pub seq: u64,
    pub drop: DropRef,
    pub created_at: i64,
    pub message_type: MessageType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    pub resends: u32,
    pub needs_resend: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SendState {
    pub next_seq: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<SendTarget>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub highest_gen: Option<u64>,
    #[serde(default)]
    pub rescues: Vec<DropCapability>,
    #[serde(default)]
    pub outbox: Vec<OutboxEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecvState {
    pub next_seq: u64,
    #[serde(default)]
    pub generations: Vec<OwnedGeneration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub highest_gen: Option<u64>,
    #[serde(default)]
    pub missing: Vec<u64>,
    #[serde(default)]
    pub seen_msg_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rescue: Option<OwnedCapability>,
    pub window: u64,
}

impl Default for RecvState {
    fn default() -> Self {
        Self {
            next_seq: 0,
            generations: Vec::new(),
            highest_gen: None,
            missing: Vec::new(),
            seen_msg_ids: Vec::new(),
            rescue: None,
            window: DEFAULT_WINDOW,
        }
    }
}

/// Both directions of one contact.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Conversation {
    pub contact_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_identity_key: Option<String>,
    pub verified: bool,
    pub servers: Vec<String>,
    #[serde(default)]
    pub send: SendState,
    #[serde(default)]
    pub recv: RecvState,
}

/// A drop the receiver should check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WatchTarget {
    Chain {
        seq: u64,
        generation: u64,
        drop: DropRef,
    },
    Rescue {
        drop: DropRef,
    },
}

impl WatchTarget {
    pub fn drop(&self) -> &DropRef {
        match self {
            WatchTarget::Chain { drop, .. } | WatchTarget::Rescue { drop } => drop,
        }
    }
}

/// What the caller observed for one watched drop.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DropStatus {
    /// The drop holds a well-formed V2 envelope.
    Present(Envelope),
    /// The drop holds bytes that are not a V2 envelope (squatted or foreign).
    Unreadable,
    /// `404`: never written, expired, or discarded.
    Absent,
    /// Transport or server error; nothing can be concluded.
    Unknown,
}

/// An outgoing message prepared by the session; the caller uploads `envelope` to `drop`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outgoing {
    pub drop: DropRef,
    pub envelope: Envelope,
    pub content: PayloadContent,
    pub capability_message: bool,
    shared_secret: [u8; 32],
}

/// A processed inbound message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Incoming {
    pub seq: u64,
    pub msg_id: String,
    pub created_at: i64,
    pub message_type: MessageType,
    pub text: Option<String>,
    pub duplicate: bool,
    pub resend_of: Option<u64>,
}

/// What one poll round changed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PollOutcome {
    pub received: Vec<Incoming>,
    pub newly_missing: Vec<u64>,
    pub invalid: Vec<u64>,
    pub delivered_msg_ids: Vec<String>,
    pub progressed: bool,
}

impl Conversation {
    /// Start a conversation from an imported bundle: the first send is a capability message.
    pub fn from_bundle(
        contact_id: impl Into<String>,
        bundle: &ContactBundle,
        own_servers: &[String],
    ) -> Result<Self> {
        bundle.validate(true)?;
        if own_servers.is_empty() {
            return Err(ProtocolError::Validation(
                "at least one own server is required to receive replies".to_string(),
            ));
        }
        let capability = bundle.initial[0].clone();
        Ok(Self {
            contact_id: contact_id.into(),
            display_name: bundle.display_name.clone(),
            peer_identity_key: Some(bundle.identity_key.clone()),
            verified: false,
            servers: own_servers.to_vec(),
            send: SendState {
                target: Some(SendTarget::Capability { capability }),
                ..SendState::default()
            },
            recv: RecvState::default(),
        })
    }

    /// Create a conversation from a capability message that arrived on one of our bundle
    /// capabilities. The sender is unknown and therefore unverified.
    pub fn from_capability_message(
        contact_id: impl Into<String>,
        own_servers: &[String],
        capability: &OwnedCapability,
        envelope: &Envelope,
    ) -> Result<(Self, Incoming)> {
        if own_servers.is_empty() {
            return Err(ProtocolError::Validation(
                "at least one own server is required to receive replies".to_string(),
            ));
        }
        let mut conversation = Self {
            contact_id: contact_id.into(),
            display_name: None,
            peer_identity_key: None,
            verified: false,
            servers: own_servers.to_vec(),
            send: SendState::default(),
            recv: RecvState::default(),
        };
        let incoming = conversation.process_capability_message(capability, envelope)?;
        Ok((conversation, incoming))
    }

    /// Drops to check now.
    pub fn watch_targets(&self) -> Vec<WatchTarget> {
        let mut targets = Vec::new();
        for owned in &self.recv.generations {
            let profile = owned.profile();
            for seq in self.recv.next_seq..self.recv.next_seq.saturating_add(self.recv.window) {
                if let Ok(drop) = chain_drop(&profile, seq) {
                    targets.push(WatchTarget::Chain {
                        seq,
                        generation: owned.generation,
                        drop,
                    });
                }
            }
        }
        if let Some(rescue) = &self.recv.rescue {
            targets.push(WatchTarget::Rescue {
                drop: DropRef {
                    server: rescue.capability.server.clone(),
                    drop_id: rescue.capability.drop_id.clone(),
                },
            });
        }
        targets
    }

    /// Prepare a text message. The caller uploads it and then calls `commit_sent`.
    pub fn prepare_text(
        &mut self,
        signing_key: &SigningKey,
        text: &str,
        created_at: i64,
    ) -> Result<Outgoing> {
        if text.is_empty() {
            return Err(ProtocolError::Validation(
                "message text must not be empty".to_string(),
            ));
        }
        self.prepare(
            signing_key,
            MessageType::Text,
            Some(text.to_string()),
            random_msg_id(),
            None,
            created_at,
        )
    }

    /// Prepare a control message carrying only acknowledgement and rotation state.
    pub fn prepare_control(
        &mut self,
        signing_key: &SigningKey,
        created_at: i64,
    ) -> Result<Outgoing> {
        self.prepare(
            signing_key,
            MessageType::Control,
            None,
            random_msg_id(),
            None,
            created_at,
        )
    }

    /// Prepare a resend of the outbox entry with `msg_id`.
    pub fn prepare_resend(
        &mut self,
        signing_key: &SigningKey,
        msg_id: &str,
        created_at: i64,
    ) -> Result<Outgoing> {
        let entry = self
            .send
            .outbox
            .iter()
            .find(|entry| entry.msg_id == msg_id)
            .cloned()
            .ok_or_else(|| ProtocolError::Validation(format!("no outbox entry for {msg_id}")))?;
        self.prepare(
            signing_key,
            entry.message_type,
            entry.text.clone(),
            entry.msg_id.clone(),
            Some(entry.original_seq),
            created_at,
        )
    }

    fn prepare(
        &mut self,
        signing_key: &SigningKey,
        message_type: MessageType,
        text: Option<String>,
        msg_id: String,
        resend_of: Option<u64>,
        created_at: i64,
    ) -> Result<Outgoing> {
        let target = self.send.target.clone().ok_or_else(|| {
            ProtocolError::Validation(
                "no send target: the peer has not established a chain and no rescue is known"
                    .to_string(),
            )
        })?;
        let seq = self.send.next_seq;
        let (drop, receive_key, capability_message) = match &target {
            SendTarget::Capability { capability } => (
                DropRef {
                    server: capability.server.clone(),
                    drop_id: capability.drop_id.clone(),
                },
                capability.recipient_key.clone(),
                true,
            ),
            SendTarget::Chain { profile } => (
                chain_drop(profile, seq)?,
                profile.receive_key.clone(),
                false,
            ),
        };

        let receive = self.advertised_generation().profile();
        let rescue = self.own_rescue().capability.clone();
        let ack = self.recv.next_seq.checked_sub(1);
        let missing = match ack {
            Some(_) if !self.recv.missing.is_empty() => Some(self.recv.missing.clone()),
            _ => None,
        };
        let content = PayloadContent {
            message_type,
            msg_id,
            created_at,
            seq,
            text,
            ack,
            missing,
            resend_of,
            receive: Some(receive),
            rescue: Some(rescue),
        };
        let sealed = seal(signing_key, &receive_key, &drop.drop_id, &content)?;
        Ok(Outgoing {
            drop,
            envelope: sealed.envelope,
            content,
            capability_message,
            shared_secret: sealed.shared_secret,
        })
    }

    /// Record a successful `201` for `outgoing`.
    pub fn commit_sent(&mut self, outgoing: &Outgoing) -> Result<()> {
        if outgoing.content.seq != self.send.next_seq {
            return Err(ProtocolError::Validation(
                "outgoing message is stale; prepare it again".to_string(),
            ));
        }
        if outgoing.capability_message {
            let Some(SendTarget::Capability { capability }) = self.send.target.clone() else {
                return Err(ProtocolError::Validation(
                    "send target changed under a capability message".to_string(),
                ));
            };
            let generation = self.send.highest_gen.map_or(0, |g| g + 1);
            let drop_id_bytes = decode_base64url(&capability.drop_id)?;
            let chain_key = derive_chain_key(&outgoing.shared_secret, &drop_id_bytes);
            self.send.highest_gen = Some(generation);
            self.send.target = Some(SendTarget::Chain {
                profile: ReceiveProfile {
                    generation,
                    chain_key: encode_base64url(&chain_key),
                    receive_key: capability.recipient_key.clone(),
                    servers: vec![capability.server.clone()],
                },
            });
            self.send
                .rescues
                .retain(|rescue| rescue.drop_id != capability.drop_id);
        }

        let seq = outgoing.content.seq;
        self.send.next_seq = seq + 1;
        if let Some(entry) = self
            .send
            .outbox
            .iter_mut()
            .find(|entry| entry.msg_id == outgoing.content.msg_id)
        {
            entry.seq = seq;
            entry.drop = outgoing.drop.clone();
            entry.resends += 1;
            entry.needs_resend = false;
        } else {
            self.send.outbox.push(OutboxEntry {
                msg_id: outgoing.content.msg_id.clone(),
                original_seq: seq,
                seq,
                drop: outgoing.drop.clone(),
                created_at: outgoing.content.created_at,
                message_type: outgoing.content.message_type,
                text: outgoing.content.text.clone(),
                resends: 0,
                needs_resend: false,
            });
        }
        Ok(())
    }

    /// Record a `409` whose stored bytes differ from ours: the chain is compromised. Switches to
    /// the newest known rescue when there is one. Returns whether a path remains.
    pub fn mark_compromised(&mut self) -> bool {
        self.send.target = self
            .send
            .rescues
            .pop()
            .map(|capability| SendTarget::Capability { capability });
        for entry in &mut self.send.outbox {
            entry.needs_resend = true;
        }
        self.send.target.is_some()
    }

    /// Record that a drop we wrote vanished before it was acknowledged.
    pub fn mark_expired(&mut self, msg_id: &str) {
        if let Some(entry) = self
            .send
            .outbox
            .iter_mut()
            .find(|entry| entry.msg_id == msg_id)
        {
            entry.needs_resend = true;
        }
    }

    /// Outbox entries that should be resent now, and entries that exceeded the resend cap
    /// (removed from the outbox and returned as undeliverable).
    pub fn take_resend_queue(&mut self) -> (Vec<String>, Vec<OutboxEntry>) {
        let mut undeliverable = Vec::new();
        self.send.outbox.retain(|entry| {
            if entry.needs_resend && entry.resends >= MAX_RESENDS {
                undeliverable.push(entry.clone());
                false
            } else {
                true
            }
        });
        let queue = self
            .send
            .outbox
            .iter()
            .filter(|entry| entry.needs_resend)
            .map(|entry| entry.msg_id.clone())
            .collect();
        (queue, undeliverable)
    }

    /// Unacknowledged entries whose drops the caller may `HEAD` to detect expiry.
    pub fn unacknowledged(&self) -> &[OutboxEntry] {
        &self.send.outbox
    }

    /// Apply one poll round. `results` pairs each watch target with what the caller observed.
    pub fn apply_poll(&mut self, results: Vec<(WatchTarget, DropStatus)>) -> Result<PollOutcome> {
        let mut outcome = PollOutcome::default();

        for (target, status) in &results {
            if let (WatchTarget::Rescue { .. }, DropStatus::Present(envelope)) = (target, status)
                && let Some(rescue) = self.recv.rescue.clone()
            {
                match self.process_capability_message(&rescue, envelope) {
                    Ok(incoming) => {
                        outcome.received.push(incoming);
                        outcome.progressed = true;
                    }
                    Err(_) => {
                        self.recv.rescue = None;
                        outcome.progressed = true;
                    }
                }
            }
        }

        loop {
            let seq = self.recv.next_seq;
            let present = results
                .iter()
                .find_map(|(target, status)| match (target, status) {
                    (
                        WatchTarget::Chain {
                            seq: s,
                            generation,
                            drop,
                        },
                        DropStatus::Present(envelope),
                    ) if *s == seq => Some((*generation, drop.clone(), Some(envelope.clone()))),
                    (
                        WatchTarget::Chain {
                            seq: s,
                            generation,
                            drop,
                        },
                        DropStatus::Unreadable,
                    ) if *s == seq => Some((*generation, drop.clone(), None)),
                    _ => None,
                });
            if let Some((generation, drop, envelope)) = present {
                let processed = envelope
                    .ok_or_else(|| ProtocolError::Validation("unreadable drop".to_string()))
                    .and_then(|envelope| self.process_chain_message(generation, &drop, &envelope));
                match processed {
                    Ok((incoming, delivered)) => {
                        outcome.delivered_msg_ids.extend(delivered);
                        outcome.received.push(incoming);
                    }
                    Err(_) => {
                        self.record_missing(seq);
                        outcome.invalid.push(seq);
                        self.recv.next_seq = seq + 1;
                    }
                }
                outcome.progressed = true;
                continue;
            }

            let statuses: Vec<&DropStatus> = results
                .iter()
                .filter_map(|(target, status)| match target {
                    WatchTarget::Chain { seq: s, .. } if *s == seq => Some(status),
                    _ => None,
                })
                .collect();
            if statuses.is_empty() || statuses.iter().any(|s| matches!(s, DropStatus::Unknown)) {
                break;
            }
            let later_present = results.iter().any(|(target, status)| {
                matches!(
                    (target, status),
                    (WatchTarget::Chain { seq: s, .. }, DropStatus::Present(_) | DropStatus::Unreadable) if *s > seq
                )
            });
            if !later_present {
                break;
            }
            self.record_missing(seq);
            outcome.newly_missing.push(seq);
            self.recv.next_seq = seq + 1;
            outcome.progressed = true;
        }

        Ok(outcome)
    }

    fn process_chain_message(
        &mut self,
        generation: u64,
        drop: &DropRef,
        envelope: &Envelope,
    ) -> Result<(Incoming, Vec<String>)> {
        let owned = self
            .recv
            .generations
            .iter()
            .find(|owned| owned.generation == generation)
            .cloned()
            .ok_or_else(|| ProtocolError::Validation(format!("unknown owned {generation}")))?;
        let opened = open(&owned.secret()?, &drop.drop_id, envelope)?;
        let payload = opened.payload;
        let expected = self.peer_identity_key.as_deref().ok_or_else(|| {
            ProtocolError::Signature("chain message before identity was bound".to_string())
        })?;
        if payload.sender_identity_key != expected {
            return Err(ProtocolError::Signature(
                "sender identity does not match the bound contact".to_string(),
            ));
        }
        if payload.content.seq != self.recv.next_seq {
            return Err(ProtocolError::Validation(format!(
                "expected seq {}, found {}",
                self.recv.next_seq, payload.content.seq
            )));
        }

        for owned in &mut self.recv.generations {
            if owned.generation == generation {
                owned.adopted = true;
            }
        }
        self.recv
            .generations
            .retain(|owned| owned.generation >= generation);

        let (incoming, delivered) = self.absorb(&payload.content);
        Ok((incoming, delivered))
    }

    fn process_capability_message(
        &mut self,
        capability: &OwnedCapability,
        envelope: &Envelope,
    ) -> Result<Incoming> {
        let opened = open(
            &capability.secret_key()?,
            &capability.capability.drop_id,
            envelope,
        )?;
        let payload = opened.payload;
        match &self.peer_identity_key {
            Some(expected) if *expected != payload.sender_identity_key => {
                return Err(ProtocolError::Signature(
                    "rescue message from an unexpected identity".to_string(),
                ));
            }
            Some(_) => {}
            None => {
                self.peer_identity_key = Some(payload.sender_identity_key.clone());
                self.verified = false;
            }
        }
        if payload.content.receive.is_none() {
            return Err(ProtocolError::Validation(
                "capability message must carry a receive profile".to_string(),
            ));
        }
        let generation = self.recv.highest_gen.map_or(0, |g| g + 1);
        let drop_id_bytes = decode_base64url(&capability.capability.drop_id)?;
        let chain_key = derive_chain_key(&opened.shared_secret, &drop_id_bytes);
        self.recv.generations.clear();
        self.recv.generations.push(OwnedGeneration {
            generation,
            chain_key: encode_base64url(&chain_key),
            receive_secret: capability.secret.clone(),
            receive_key: capability.capability.recipient_key.clone(),
            servers: vec![capability.capability.server.clone()],
            adopted: true,
        });
        self.recv.highest_gen = Some(generation);
        if self
            .recv
            .rescue
            .as_ref()
            .is_some_and(|own| own.capability.drop_id == capability.capability.drop_id)
        {
            self.recv.rescue = None;
        }

        // A rescue may legitimately reuse a sequence number we already gave up on (for
        // example after a squatted drop); otherwise everything below it was lost.
        for seq in self.recv.next_seq..payload.content.seq {
            self.record_missing(seq);
        }
        self.recv.missing.retain(|seq| *seq != payload.content.seq);
        let (incoming, _) = self.absorb(&payload.content);
        Ok(incoming)
    }

    /// Apply the conversation-state effects of a verified payload and advance `next_seq`.
    fn absorb(&mut self, content: &PayloadContent) -> (Incoming, Vec<String>) {
        if let Some(resend_of) = content.resend_of {
            self.recv.missing.retain(|seq| *seq != resend_of);
        }
        let delivered = self.apply_ack(content.ack, content.missing.as_deref());
        if let Some(profile) = &content.receive
            && self.send.highest_gen.is_none_or(|g| profile.generation > g)
        {
            self.send.target = Some(SendTarget::Chain {
                profile: profile.clone(),
            });
            self.send.highest_gen = Some(profile.generation);
        }
        if let Some(rescue) = &content.rescue {
            self.send
                .rescues
                .retain(|known| known.drop_id != rescue.drop_id);
            self.send.rescues.push(rescue.clone());
            while self.send.rescues.len() > MAX_PEER_RESCUES {
                self.send.rescues.remove(0);
            }
        }

        let duplicate = self.recv.seen_msg_ids.contains(&content.msg_id);
        if !duplicate {
            self.recv.seen_msg_ids.push(content.msg_id.clone());
            while self.recv.seen_msg_ids.len() > MAX_SEEN_MSG_IDS {
                self.recv.seen_msg_ids.remove(0);
            }
        }
        self.recv.next_seq = self.recv.next_seq.max(content.seq + 1);
        (
            Incoming {
                seq: content.seq,
                msg_id: content.msg_id.clone(),
                created_at: content.created_at,
                message_type: content.message_type,
                text: content.text.clone(),
                duplicate,
                resend_of: content.resend_of,
            },
            delivered,
        )
    }

    fn apply_ack(&mut self, ack: Option<u64>, missing: Option<&[u64]>) -> Vec<String> {
        let Some(ack) = ack else {
            return Vec::new();
        };
        let missing = missing.unwrap_or_default();
        let mut delivered = Vec::new();
        self.send.outbox.retain_mut(|entry| {
            if entry.seq > ack {
                return true;
            }
            if missing.contains(&entry.seq) {
                entry.needs_resend = true;
                true
            } else {
                delivered.push(entry.msg_id.clone());
                false
            }
        });
        delivered
    }

    fn record_missing(&mut self, seq: u64) {
        if !self.recv.missing.contains(&seq) {
            self.recv.missing.push(seq);
            self.recv.missing.sort_unstable();
        }
    }

    fn advertised_generation(&mut self) -> &OwnedGeneration {
        if let Some(index) = self
            .recv
            .generations
            .iter()
            .position(|owned| !owned.adopted)
        {
            return &self.recv.generations[index];
        }
        let generation = self.recv.highest_gen.map_or(0, |g| g + 1);
        let secret = StaticSecret::random_from_rng(OsRng);
        let mut chain_key = [0_u8; 32];
        OsRng.fill_bytes(&mut chain_key);
        self.recv.generations.push(OwnedGeneration {
            generation,
            chain_key: encode_base64url(&chain_key),
            receive_secret: encode_base64url(&secret.to_bytes()),
            receive_key: tagged_base64("x25519", PublicKey::from(&secret).as_bytes()),
            servers: self.servers.clone(),
            adopted: false,
        });
        self.recv.highest_gen = Some(generation);
        self.recv.generations.last().expect("owned was just pushed")
    }

    fn own_rescue(&mut self) -> &OwnedCapability {
        if self.recv.rescue.is_none() {
            let server = self.servers[self.send.next_seq as usize % self.servers.len()].clone();
            self.recv.rescue = Some(OwnedCapability::generate(&server));
        }
        self.recv.rescue.as_ref().expect("rescue was just created")
    }
}

fn random_msg_id() -> String {
    let mut bytes = [0_u8; 16];
    OsRng.fill_bytes(&mut bytes);
    encode_base64url(&bytes)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    /// In-memory write-once drop store standing in for one or more servers.
    #[derive(Default)]
    struct Store {
        drops: HashMap<(String, String), Envelope>,
    }

    impl Store {
        fn put(&mut self, outgoing: &Outgoing) -> bool {
            let key = (outgoing.drop.server.clone(), outgoing.drop.drop_id.clone());
            if self.drops.contains_key(&key) {
                return false;
            }
            self.drops.insert(key, outgoing.envelope.clone());
            true
        }

        fn expire(&mut self, drop: &DropRef) {
            self.drops
                .remove(&(drop.server.clone(), drop.drop_id.clone()));
        }

        fn poll(&self, conversation: &Conversation) -> Vec<(WatchTarget, DropStatus)> {
            conversation
                .watch_targets()
                .into_iter()
                .map(|target| {
                    let key = (target.drop().server.clone(), target.drop().drop_id.clone());
                    let status = match self.drops.get(&key) {
                        Some(envelope) => DropStatus::Present(envelope.clone()),
                        None => DropStatus::Absent,
                    };
                    (target, status)
                })
                .collect()
        }
    }

    struct Peer {
        signing_key: SigningKey,
        conversation: Conversation,
    }

    impl Peer {
        fn send(&mut self, store: &mut Store, text: &str) -> Outgoing {
            let outgoing = self
                .conversation
                .prepare_text(&self.signing_key, text, 1_000)
                .unwrap();
            assert!(store.put(&outgoing), "drop already used");
            self.conversation.commit_sent(&outgoing).unwrap();
            outgoing
        }

        fn drain(&mut self, store: &Store) -> Vec<Incoming> {
            let mut all = Vec::new();
            loop {
                let outcome = self
                    .conversation
                    .apply_poll(store.poll(&self.conversation))
                    .unwrap();
                all.extend(outcome.received);
                if !outcome.progressed {
                    return all;
                }
            }
        }

        fn resend_all(&mut self, store: &mut Store) {
            let (queue, undeliverable) = self.conversation.take_resend_queue();
            assert!(undeliverable.is_empty());
            for msg_id in queue {
                let outgoing = self
                    .conversation
                    .prepare_resend(&self.signing_key, &msg_id, 1_001)
                    .unwrap();
                assert!(store.put(&outgoing));
                self.conversation.commit_sent(&outgoing).unwrap();
            }
        }
    }

    fn pair() -> (Peer, Peer, OwnedCapability) {
        let bob_key = SigningKey::from_bytes(&[11_u8; 32]);
        let bob_capability = OwnedCapability::generate("https://bob.example");
        let bundle = ContactBundle {
            v: 2,
            display_name: Some("Bob".to_string()),
            identity_key: tagged_base64("ed25519", bob_key.verifying_key().as_bytes()),
            initial: vec![bob_capability.capability.clone()],
        };
        let alice_key = SigningKey::from_bytes(&[12_u8; 32]);
        let alice = Peer {
            signing_key: alice_key,
            conversation: Conversation::from_bundle(
                "bob",
                &bundle,
                &[
                    "https://a1.example".to_string(),
                    "https://a2.example".to_string(),
                ],
            )
            .unwrap(),
        };
        let bob = Peer {
            signing_key: bob_key,
            conversation: Conversation {
                contact_id: "alice".to_string(),
                display_name: None,
                peer_identity_key: None,
                verified: false,
                servers: vec!["https://bob.example".to_string()],
                send: SendState::default(),
                recv: RecvState::default(),
            },
        };
        (alice, bob, bob_capability)
    }

    fn bootstrap(store: &mut Store) -> (Peer, Peer) {
        let (mut alice, mut bob, bob_capability) = pair();
        let first = alice.send(store, "hi bob");
        assert!(first.capability_message);
        let envelope = store
            .drops
            .get(&(first.drop.server.clone(), first.drop.drop_id.clone()))
            .unwrap()
            .clone();
        let (conversation, incoming) = Conversation::from_capability_message(
            "alice",
            &["https://bob.example".to_string()],
            &bob_capability,
            &envelope,
        )
        .unwrap();
        assert_eq!(incoming.text.as_deref(), Some("hi bob"));
        bob.conversation = conversation;
        (alice, bob)
    }

    #[test]
    fn sender_writes_many_messages_without_a_reply() {
        let mut store = Store::default();
        let (mut alice, mut bob) = bootstrap(&mut store);

        for i in 0..20 {
            alice.send(&mut store, &format!("msg {i}"));
        }
        let received = bob.drain(&store);
        assert_eq!(received.len(), 20);
        assert_eq!(received[0].seq, 1);
        assert_eq!(received[19].text.as_deref(), Some("msg 19"));
        assert_eq!(bob.conversation.recv.next_seq, 21);
    }

    #[test]
    fn reply_acknowledges_rotates_and_both_directions_continue() {
        let mut store = Store::default();
        let (mut alice, mut bob) = bootstrap(&mut store);
        alice.send(&mut store, "one");
        alice.send(&mut store, "two");
        bob.drain(&store);

        let reply = bob.send(&mut store, "got them");
        assert_eq!(reply.content.ack, Some(2));
        assert!(reply.content.receive.is_some());
        assert_eq!(reply.content.receive.as_ref().unwrap().generation, 1);

        let alice_got = alice.drain(&store);
        assert_eq!(alice_got.len(), 1);
        assert!(
            alice.conversation.send.outbox.is_empty(),
            "ack cleared the outbox"
        );
        match &alice.conversation.send.target {
            Some(SendTarget::Chain { profile }) => assert_eq!(profile.generation, 1),
            other => panic!("expected chain target, got {other:?}"),
        }

        alice.send(&mut store, "three on generation 1");
        let bob_got = bob.drain(&store);
        assert_eq!(bob_got.len(), 1);
        assert_eq!(bob_got[0].text.as_deref(), Some("three on generation 1"));
        assert_eq!(bob.conversation.recv.generations.len(), 1);
        assert_eq!(bob.conversation.recv.generations[0].generation, 1);
        assert!(bob.conversation.recv.generations[0].adopted);
    }

    #[test]
    fn expired_drop_is_reported_missing_and_resent() {
        let mut store = Store::default();
        let (mut alice, mut bob) = bootstrap(&mut store);
        let lost = alice.send(&mut store, "lost");
        alice.send(&mut store, "kept");
        store.expire(&lost.drop);

        let received = bob.drain(&store);
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].text.as_deref(), Some("kept"));
        assert_eq!(bob.conversation.recv.missing, vec![1]);

        let reply = bob.send(&mut store, "where is one?");
        assert_eq!(reply.content.ack, Some(2));
        assert_eq!(reply.content.missing, Some(vec![1]));

        alice.drain(&store);
        let needs: Vec<_> = alice
            .conversation
            .send
            .outbox
            .iter()
            .filter(|entry| entry.needs_resend)
            .map(|entry| entry.text.clone())
            .collect();
        assert_eq!(needs, vec![Some("lost".to_string())]);
        alice.resend_all(&mut store);

        let received = bob.drain(&store);
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].text.as_deref(), Some("lost"));
        assert_eq!(received[0].resend_of, Some(1));
        assert!(!received[0].duplicate);
        assert!(bob.conversation.recv.missing.is_empty());
    }

    #[test]
    fn resend_of_a_message_the_peer_already_has_is_a_duplicate() {
        let mut store = Store::default();
        let (mut alice, mut bob) = bootstrap(&mut store);
        let first = alice.send(&mut store, "once");
        bob.drain(&store);
        alice.conversation.mark_expired(&first.content.msg_id);
        alice.resend_all(&mut store);

        let received = bob.drain(&store);
        assert_eq!(received.len(), 1);
        assert!(received[0].duplicate);
    }

    #[test]
    fn compromised_chain_recovers_through_rescue() {
        let mut store = Store::default();
        let (mut alice, mut bob) = bootstrap(&mut store);
        alice.send(&mut store, "before");
        bob.drain(&store);
        bob.send(&mut store, "ack + rescue");
        alice.drain(&store);
        assert_eq!(alice.conversation.send.rescues.len(), 1);

        // An attacker who knows the chain key squats Alice's next drop with garbage.
        let Some(SendTarget::Chain { profile }) = alice.conversation.send.target.clone() else {
            panic!("alice should be on a chain");
        };
        let squatted_drop = chain_drop(&profile, alice.conversation.send.next_seq).unwrap();
        let mallory_key = SigningKey::from_bytes(&[99_u8; 32]);
        let garbage = seal(
            &mallory_key,
            &OwnedCapability::generate("https://x.example")
                .capability
                .recipient_key,
            &squatted_drop.drop_id,
            &PayloadContent {
                message_type: MessageType::Control,
                msg_id: encode_base64url(&[1_u8; 16]),
                created_at: 0,
                seq: 0,
                text: None,
                ack: None,
                missing: None,
                resend_of: None,
                receive: None,
                rescue: None,
            },
        )
        .unwrap();
        store.drops.insert(
            (squatted_drop.server.clone(), squatted_drop.drop_id.clone()),
            garbage.envelope,
        );
        let squat = alice
            .conversation
            .prepare_text(&alice.signing_key, "squatted", 999)
            .unwrap();
        assert!(!store.put(&squat), "409 with foreign bytes");
        assert!(alice.conversation.mark_compromised());
        let outgoing = alice.send(&mut store, "via rescue");
        assert!(outgoing.capability_message);

        let received = bob.drain(&store);
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].text.as_deref(), Some("via rescue"));
        assert!(bob.conversation.recv.rescue.is_none(), "rescue consumed");
        assert_eq!(bob.conversation.recv.generations.len(), 1);

        bob.send(&mut store, "new chain works");
        alice.drain(&store);
        alice.send(&mut store, "and back");
        assert_eq!(bob.drain(&store).len(), 1);
    }

    #[test]
    fn foreign_identity_on_chain_is_rejected() {
        let mut store = Store::default();
        let (alice, mut bob) = bootstrap(&mut store);
        let mut mallory = Peer {
            signing_key: SigningKey::from_bytes(&[99_u8; 32]),
            conversation: alice.conversation.clone(),
        };
        mallory.send(&mut store, "impostor");
        let outcome = bob
            .conversation
            .apply_poll(store.poll(&bob.conversation))
            .unwrap();
        assert!(outcome.received.is_empty());
        assert_eq!(outcome.invalid, vec![1]);
    }
}
