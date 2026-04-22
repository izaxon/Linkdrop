use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow, bail};
use linkdrop_protocol::{
    ClientStateFile, ContactBundle, ContactRecord, ContactsFile, DecryptedPayload, DropRef,
    IdentityFile, MessageDirection, MessageEnvelope, MessageRecord, MessageStatus, MessagesFile,
    WatchedDrop, decrypt_envelope, encrypt_payload_for_contact, generate_contact_id,
    generate_drop_id, validate_server_url,
};
use serde::{Serialize, de::DeserializeOwned};
use url::Url;

#[derive(Debug, Clone)]
pub struct LinkdropApp {
    state_dir: PathBuf,
    client: reqwest::blocking::Client,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PollSummary {
    pub received: usize,
    pub duplicates: usize,
    pub invalid: usize,
}

impl LinkdropApp {
    pub fn new(state_dir: impl Into<PathBuf>) -> Result<Self> {
        let client = reqwest::blocking::Client::builder()
            .build()
            .context("failed to construct HTTP client")?;
        Ok(Self {
            state_dir: state_dir.into(),
            client,
        })
    }

    pub fn init(&self, name: &str) -> Result<IdentityFile> {
        if name.trim().is_empty() {
            bail!("display name must not be empty");
        }
        self.ensure_state_dir()?;

        let identity = IdentityFile::generate(name);
        identity.validate()?;

        self.write_json(&self.identity_path(), &identity)?;
        self.write_json(&self.contacts_path(), &ContactsFile::default())?;
        self.write_json(&self.messages_path(), &MessagesFile::default())?;
        self.write_json(&self.client_state_path(), &ClientStateFile::default())?;
        Ok(identity)
    }

    pub fn whoami(&self) -> Result<IdentityFile> {
        let identity = self.read_required_json::<IdentityFile>(&self.identity_path())?;
        identity.validate()?;
        Ok(identity)
    }

    pub fn export_contact_bundle(&self, servers: &[String]) -> Result<ContactBundle> {
        if servers.is_empty() {
            bail!("at least one --server value is required");
        }

        let identity = self.whoami()?;
        let mut client_state =
            self.read_optional_json::<ClientStateFile>(&self.client_state_path())?;

        let mut initial_drops = Vec::with_capacity(servers.len());
        for server in servers {
            validate_server_url(server, true)
                .with_context(|| format!("invalid server URL {server}"))?;
            let drop_ref = DropRef {
                server: server.clone(),
                drop_id: generate_drop_id(),
            };
            initial_drops.push(drop_ref.clone());
            client_state.watched_drops.push(WatchedDrop {
                drop: drop_ref,
                contact_id: None,
            });
        }

        let bundle = ContactBundle {
            v: 1,
            display_name: Some(identity.display_name.clone()),
            identity_key: identity.tagged_identity_public_key(),
            prekey: identity.tagged_prekey_public_key(),
            initial_drops,
        };
        bundle.validate(true)?;
        self.write_json(&self.client_state_path(), &client_state)?;
        Ok(bundle)
    }

    pub fn import_contact_bundle(&self, bundle_path: &Path) -> Result<ContactRecord> {
        let raw = fs::read_to_string(bundle_path)
            .with_context(|| format!("failed to read bundle file {}", bundle_path.display()))?;
        let bundle: ContactBundle =
            serde_json::from_str(&raw).context("failed to parse contact bundle")?;
        bundle.validate(true)?;

        let mut contacts = self.read_optional_json::<ContactsFile>(&self.contacts_path())?;
        if let Some(existing) = contacts
            .contacts
            .iter_mut()
            .find(|contact| contact.identity_key == bundle.identity_key)
        {
            existing.display_name = bundle.display_name.clone();
            existing.prekey = Some(bundle.prekey.clone());
            existing.initial_drops = bundle.initial_drops.clone();
            existing.next_outgoing_drop = None;
            let contact = existing.clone();
            self.write_json(&self.contacts_path(), &contacts)?;
            return Ok(contact);
        }

        let contact = ContactRecord {
            contact_id: generate_contact_id(),
            display_name: bundle.display_name.clone(),
            identity_key: bundle.identity_key,
            prekey: Some(bundle.prekey),
            initial_drops: bundle.initial_drops,
            next_outgoing_drop: None,
        };
        contacts.contacts.push(contact.clone());
        self.write_json(&self.contacts_path(), &contacts)?;
        Ok(contact)
    }

    pub fn list_contacts(&self) -> Result<Vec<ContactRecord>> {
        Ok(self
            .read_optional_json::<ContactsFile>(&self.contacts_path())?
            .contacts)
    }

    pub fn send_message(&self, contact_id: &str, text: &str) -> Result<MessageRecord> {
        if text.trim().is_empty() {
            bail!("message text must not be empty");
        }

        let identity = self.whoami()?;
        let mut contacts = self.read_optional_json::<ContactsFile>(&self.contacts_path())?;
        let mut messages = self.read_optional_json::<MessagesFile>(&self.messages_path())?;
        let mut client_state =
            self.read_optional_json::<ClientStateFile>(&self.client_state_path())?;

        let contact = contacts
            .contacts
            .iter_mut()
            .find(|contact| contact.contact_id == contact_id)
            .ok_or_else(|| anyhow!("contact {contact_id} not found"))?;
        let used_drop = if let Some(drop) = contact.next_outgoing_drop.take() {
            drop
        } else if !contact.initial_drops.is_empty() {
            contact.initial_drops.remove(0)
        } else {
            bail!("contact {contact_id} has no available drop to send to");
        };

        let recipient_prekey = contact.prekey.as_deref().ok_or_else(|| {
            anyhow!("contact {contact_id} has no prekey; import their contact bundle first")
        })?;
        let reply_drop = DropRef {
            server: used_drop.server.clone(),
            drop_id: generate_drop_id(),
        };
        let prev_msg_id = messages
            .messages
            .iter()
            .rev()
            .find(|message| message.contact_id == contact_id)
            .map(|message| message.msg_id.clone());
        let payload = DecryptedPayload {
            text: text.to_string(),
            prev_msg_id,
        };
        let envelope =
            encrypt_payload_for_contact(&identity, recipient_prekey, reply_drop.clone(), &payload)?;

        let response = self
            .client
            .put(drop_ref_url(&used_drop)?)
            .header("content-type", "application/json")
            .body(serde_json::to_vec(&envelope)?)
            .send()
            .with_context(|| format!("failed to send message to {}", used_drop.server))?;

        let status = match response.status().as_u16() {
            201 => MessageStatus::Sent,
            400 => bail!("server rejected the envelope as invalid"),
            404 => bail!("drop endpoint was not found on the server"),
            409 => MessageStatus::Failed,
            413 => bail!("server rejected the envelope because it was too large"),
            code if code >= 500 => MessageStatus::Failed,
            code => bail!("unexpected server status {code}"),
        };

        let record = MessageRecord {
            msg_id: envelope.msg_id.clone(),
            contact_id: contact_id.to_string(),
            direction: MessageDirection::Outbound,
            created_at: envelope.created_at,
            text: text.to_string(),
            status,
            used_drop: Some(used_drop.clone()),
            reply_drop_generated: Some(reply_drop.clone()),
            received_from_drop: None,
            prev_msg_id: payload.prev_msg_id.clone(),
        };

        if record.status == MessageStatus::Sent {
            client_state.watched_drops.push(WatchedDrop {
                drop: reply_drop,
                contact_id: Some(contact_id.to_string()),
            });
        }
        messages.messages.push(record.clone());
        self.write_json(&self.contacts_path(), &contacts)?;
        self.write_json(&self.messages_path(), &messages)?;
        self.write_json(&self.client_state_path(), &client_state)?;
        Ok(record)
    }

    pub fn poll(&self) -> Result<PollSummary> {
        let identity = self.whoami()?;
        let mut contacts = self.read_optional_json::<ContactsFile>(&self.contacts_path())?;
        let mut messages = self.read_optional_json::<MessagesFile>(&self.messages_path())?;
        let mut client_state =
            self.read_optional_json::<ClientStateFile>(&self.client_state_path())?;
        let watched = client_state.watched_drops.clone();
        let mut keep = Vec::new();
        let mut summary = PollSummary {
            received: 0,
            duplicates: 0,
            invalid: 0,
        };

        for watch in watched {
            let head = self
                .client
                .head(drop_ref_url(&watch.drop)?)
                .send()
                .with_context(|| format!("failed to poll {}", watch.drop.server))?;

            if head.status().as_u16() == 404 {
                keep.push(watch);
                continue;
            }
            if !head.status().is_success() {
                bail!("polling {} returned {}", watch.drop.server, head.status());
            }

            let response = self
                .client
                .get(drop_ref_url(&watch.drop)?)
                .send()
                .with_context(|| format!("failed to fetch {}", watch.drop.server))?;
            if response.status().as_u16() == 404 {
                keep.push(watch);
                continue;
            }
            if !response.status().is_success() {
                bail!(
                    "fetching {} returned {}",
                    watch.drop.server,
                    response.status()
                );
            }

            let envelope: MessageEnvelope = response.json().context("failed to decode envelope")?;
            envelope.validate(true)?;

            let contact_index = match watch.contact_id.as_ref().and_then(|id| {
                contacts
                    .contacts
                    .iter()
                    .position(|contact| &contact.contact_id == id)
            }) {
                Some(index) => index,
                None => contacts
                    .contacts
                    .iter()
                    .position(|contact| contact.identity_key == envelope.sender_identity_key)
                    .unwrap_or_else(|| {
                        contacts.contacts.push(ContactRecord {
                            contact_id: generate_contact_id(),
                            display_name: None,
                            identity_key: envelope.sender_identity_key.clone(),
                            prekey: None,
                            initial_drops: Vec::new(),
                            next_outgoing_drop: None,
                        });
                        contacts.contacts.len() - 1
                    }),
            };
            let contact_id = contacts.contacts[contact_index].contact_id.clone();

            if messages.messages.iter().any(|message| {
                message.contact_id == contact_id && message.msg_id == envelope.msg_id
            }) {
                summary.duplicates += 1;
                continue;
            }

            contacts.contacts[contact_index].next_outgoing_drop = Some(envelope.reply_drop.clone());

            match decrypt_envelope(&identity, &envelope) {
                Ok(payload) => {
                    messages.messages.push(MessageRecord {
                        msg_id: envelope.msg_id,
                        contact_id,
                        direction: MessageDirection::Inbound,
                        created_at: envelope.created_at,
                        text: payload.text,
                        status: MessageStatus::Received,
                        used_drop: None,
                        reply_drop_generated: None,
                        received_from_drop: Some(watch.drop),
                        prev_msg_id: payload.prev_msg_id,
                    });
                    summary.received += 1;
                }
                Err(_) => {
                    messages.messages.push(MessageRecord {
                        msg_id: envelope.msg_id,
                        contact_id,
                        direction: MessageDirection::Inbound,
                        created_at: envelope.created_at,
                        text: "[unreadable message]".to_string(),
                        status: MessageStatus::Invalid,
                        used_drop: None,
                        reply_drop_generated: None,
                        received_from_drop: Some(watch.drop),
                        prev_msg_id: None,
                    });
                    summary.invalid += 1;
                }
            }
        }

        client_state.watched_drops = keep;
        self.write_json(&self.contacts_path(), &contacts)?;
        self.write_json(&self.messages_path(), &messages)?;
        self.write_json(&self.client_state_path(), &client_state)?;
        Ok(summary)
    }

    pub fn inbox(&self) -> Result<Vec<MessageRecord>> {
        let mut inbox: Vec<_> = self
            .read_optional_json::<MessagesFile>(&self.messages_path())?
            .messages
            .into_iter()
            .filter(|message| message.direction == MessageDirection::Inbound)
            .collect();
        inbox.sort_by_key(|message| message.created_at);
        Ok(inbox)
    }

    pub fn history(&self, contact_id: &str) -> Result<Vec<MessageRecord>> {
        let mut history: Vec<_> = self
            .read_optional_json::<MessagesFile>(&self.messages_path())?
            .messages
            .into_iter()
            .filter(|message| message.contact_id == contact_id)
            .collect();
        history.sort_by_key(|message| message.created_at);
        Ok(history)
    }

    pub fn process_incoming_envelope(
        &self,
        watch: WatchedDrop,
        envelope: MessageEnvelope,
    ) -> Result<PollSummary> {
        let identity = self.whoami()?;
        let mut contacts = self.read_optional_json::<ContactsFile>(&self.contacts_path())?;
        let mut messages = self.read_optional_json::<MessagesFile>(&self.messages_path())?;
        let mut client_state =
            self.read_optional_json::<ClientStateFile>(&self.client_state_path())?;

        client_state
            .watched_drops
            .retain(|candidate| candidate.drop != watch.drop);

        let contact_index = match watch.contact_id.as_ref().and_then(|id| {
            contacts
                .contacts
                .iter()
                .position(|contact| &contact.contact_id == id)
        }) {
            Some(index) => index,
            None => contacts
                .contacts
                .iter()
                .position(|contact| contact.identity_key == envelope.sender_identity_key)
                .unwrap_or_else(|| {
                    contacts.contacts.push(ContactRecord {
                        contact_id: generate_contact_id(),
                        display_name: None,
                        identity_key: envelope.sender_identity_key.clone(),
                        prekey: None,
                        initial_drops: Vec::new(),
                        next_outgoing_drop: None,
                    });
                    contacts.contacts.len() - 1
                }),
        };
        let contact_id = contacts.contacts[contact_index].contact_id.clone();

        let mut summary = PollSummary {
            received: 0,
            duplicates: 0,
            invalid: 0,
        };

        if messages
            .messages
            .iter()
            .any(|message| message.contact_id == contact_id && message.msg_id == envelope.msg_id)
        {
            summary.duplicates += 1;
        } else {
            contacts.contacts[contact_index].next_outgoing_drop = Some(envelope.reply_drop.clone());
            match decrypt_envelope(&identity, &envelope) {
                Ok(payload) => {
                    messages.messages.push(MessageRecord {
                        msg_id: envelope.msg_id,
                        contact_id,
                        direction: MessageDirection::Inbound,
                        created_at: envelope.created_at,
                        text: payload.text,
                        status: MessageStatus::Received,
                        used_drop: None,
                        reply_drop_generated: None,
                        received_from_drop: Some(watch.drop),
                        prev_msg_id: payload.prev_msg_id,
                    });
                    summary.received += 1;
                }
                Err(_) => {
                    messages.messages.push(MessageRecord {
                        msg_id: envelope.msg_id,
                        contact_id,
                        direction: MessageDirection::Inbound,
                        created_at: envelope.created_at,
                        text: "[unreadable message]".to_string(),
                        status: MessageStatus::Invalid,
                        used_drop: None,
                        reply_drop_generated: None,
                        received_from_drop: Some(watch.drop),
                        prev_msg_id: None,
                    });
                    summary.invalid += 1;
                }
            }
        }

        self.write_json(&self.contacts_path(), &contacts)?;
        self.write_json(&self.messages_path(), &messages)?;
        self.write_json(&self.client_state_path(), &client_state)?;
        Ok(summary)
    }

    fn ensure_state_dir(&self) -> Result<()> {
        fs::create_dir_all(&self.state_dir).with_context(|| {
            format!(
                "failed to create state directory {}",
                self.state_dir.display()
            )
        })
    }

    fn identity_path(&self) -> PathBuf {
        self.state_dir.join("identity.json")
    }

    fn contacts_path(&self) -> PathBuf {
        self.state_dir.join("contacts.json")
    }

    fn messages_path(&self) -> PathBuf {
        self.state_dir.join("messages.json")
    }

    fn client_state_path(&self) -> PathBuf {
        self.state_dir.join("client.json")
    }

    fn read_optional_json<T>(&self, path: &Path) -> Result<T>
    where
        T: DeserializeOwned + Default,
    {
        if !path.exists() {
            return Ok(T::default());
        }
        self.read_required_json(path)
    }

    fn read_required_json<T>(&self, path: &Path) -> Result<T>
    where
        T: DeserializeOwned,
    {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        serde_json::from_str(&raw).with_context(|| format!("failed to parse {}", path.display()))
    }

    fn write_json<T>(&self, path: &Path, value: &T) -> Result<()>
    where
        T: Serialize,
    {
        self.ensure_state_dir()?;
        let raw = serde_json::to_string_pretty(value)?;
        fs::write(path, raw).with_context(|| format!("failed to write {}", path.display()))
    }
}

fn drop_ref_url(drop: &DropRef) -> Result<Url> {
    let mut base = validate_server_url(&drop.server, true)?;
    if !base.path().ends_with('/') {
        let path = format!("{}/", base.path().trim_end_matches('/'));
        base.set_path(&path);
    }
    base.join(&format!("drop/{}", drop.drop_id))
        .with_context(|| format!("failed to build drop URL for {}", drop.server))
}

pub fn format_whoami(identity: &IdentityFile) -> String {
    format!(
        "display_name: {}\nidentity_key: {}\nprekey: {}",
        identity.display_name,
        identity.tagged_identity_public_key(),
        identity.tagged_prekey_public_key()
    )
}

pub fn format_contacts(contacts: &[ContactRecord]) -> String {
    if contacts.is_empty() {
        return "no contacts".to_string();
    }
    contacts
        .iter()
        .map(|contact| {
            format!(
                "{}\t{}\t{}",
                contact.contact_id,
                contact
                    .display_name
                    .clone()
                    .unwrap_or_else(|| "(unnamed)".to_string()),
                contact.identity_key
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn format_messages(messages: &[MessageRecord]) -> String {
    if messages.is_empty() {
        return "no messages".to_string();
    }
    messages
        .iter()
        .map(|message| {
            format!(
                "{}\t{:?}\t{:?}\t{}",
                message.created_at, message.direction, message.status, message.text
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn format_poll_summary(summary: &PollSummary) -> String {
    format!(
        "received: {}, duplicates: {}, invalid: {}",
        summary.received, summary.duplicates, summary.invalid
    )
}
