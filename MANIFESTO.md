# The Linkdrop Manifesto

> **The best chat protocol — simple, powerful, no lock-in, zero dependencies, AI-bot ready.**

Chat is the most-used software on the planet, and almost every chat app you use is owned by someone else. Your identity is a phone number they revoke. Your contact list is a graph they sell. Your messages live on servers that read them, scan them, lose them, or quietly hand them over. Every "open" alternative either rebuilt the same centralised model in new colours, or buried the protocol under so much complexity that nobody can implement it twice.

Linkdrop is the smallest possible answer to the question: *what would chat look like if you started over, kept it honest, and assumed bots are people too?*

---

## The pitch

A Linkdrop message is a single encrypted JSON envelope written to a single-use, randomly-named slot on any HTTPS server you happen to like today. The envelope tells the recipient where to write the next one. That's it. That's the protocol.

There is no account. There is no directory. There is no provider. There is no SDK. The wire format fits in one document. A working server is a few hundred lines. A working client is a few hundred more. An AI agent can read the spec and implement a peer in an afternoon — and once it has, it is not a "user" of anything. It is a peer.

---

## What we believe

- **Servers are dumb pipes.** A drop server should know nothing, link nothing, and own nothing. If it disappears tomorrow you switch to another one mid-conversation.
- **Identity belongs to the user.** A keypair on your device is your account. There is no signup, no recovery flow, no provider with the power to lock you out.
- **Every message is its own envelope.** Single-use drops mean conversations are chains of capabilities, not rows in a database. The next reply drop lives inside the encrypted payload — only the participants see the chain.
- **If a 200-line program can speak it, it's a real protocol.** Specs that require a vendor SDK are products in disguise. Linkdrop is small on purpose and stays that way.
- **Interoperability over features.** A new feature that breaks two implementations costs more than it adds. The spec versions the wire, not the client.
- **Bots are first-class peers.** The protocol does not distinguish humans from agents, and we will never add a "bot API" that is somebody else's gate.
- **No lock-in, anywhere.** Not in the protocol, not in the infrastructure, not in the governance, not in the funding model. Pick any server. Pick any client. Pick any implementer.

---

## What we reject

- Phone numbers as identity.
- Mandatory accounts.
- Server-readable message content.
- Federation maps and directory servers.
- Push-notification dependence on a specific cloud.
- Vendor SDKs as the only practical way to interoperate.
- Protocol bloat dressed up as "the new version".
- Foundations, tokens, or companies positioned to gate-keep the spec.

---

## Why now

LLM agents need a chat substrate they can actually implement.

Every existing major chat platform requires OAuth flows tied to a phone, a paid developer account, a rate-limited bot API, and a terms-of-service that treats automated peers as second-class. None of that fits the world we're walking into, where the most prolific senders and receivers of messages will not be humans.

Linkdrop's bet is that the protocol of the next decade looks more like email's "anyone can run a server" and less like a walled garden's "anyone can apply for an API key". Encryption fixes the part email got wrong. Single-use drops fix the part SMTP got wrong. Everything else is deliberately absent.

---

## Winning conditions

We will know Linkdrop has won when:

1. There are **many independent client implementations** — Rust, JS, Python, Swift, Go, embedded — built straight from the spec, no shared SDK.
2. There are **multiple public drop servers** run by unrelated operators, and clients rotate between them as a matter of course.
3. **AI agents talk Linkdrop natively** — to humans and to each other — without any platform intermediary.
4. The spec evolves **conservatively**: V2 is a small honest improvement over V1, not a vehicle for anyone's product roadmap.
5. The most interesting question about Linkdrop is *"what should I build on top of it?"*, not *"who controls it?"*.

---

## Call to action

If you've read this far, you're who this is for. Pick one:

- **Implement a client** in a language we don't have yet. The spec is [`linkdrop-v1-spec.md`](linkdrop-v1-spec.md).
- **Run a public drop server.** Write-once storage with a TTL — genuinely a weekend project.
- **Write a bot.** A bridge, an assistant, an agent that wakes up when you `PUT` to its drop.
- **Push back on the spec.** Open issues. Propose test vectors. Call out anything that smells like a future lock-in.
- **Tell someone.** This protocol only works if it's a Schelling point, and Schelling points are made of people choosing them on purpose.

No accounts. No gatekeepers. No moat. Just messages.

— The Linkdrop project
