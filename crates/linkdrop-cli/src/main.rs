use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use linkdrop_cli::{
    LinkdropApp, format_contacts, format_messages, format_poll_summary, format_servers,
    format_v2_conversations, format_v2_messages, format_v2_poll_summary, format_whoami,
};

#[derive(Debug, Parser)]
#[command(name = "linkdrop")]
struct Cli {
    #[arg(long, default_value = ".linkdrop")]
    state_dir: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Init {
        #[arg(long)]
        name: String,
    },
    Whoami,
    Contact {
        #[command(subcommand)]
        command: ContactCommand,
    },
    Contacts {
        #[command(subcommand)]
        command: ContactsCommand,
    },
    Send {
        #[arg(long)]
        to: String,
        #[arg(long)]
        text: String,
        #[arg(long, default_value_t = false)]
        unsigned: bool,
    },
    Poll,
    Inbox,
    History {
        #[arg(long)]
        contact: String,
    },
    Server {
        #[command(subcommand)]
        command: ServerCommand,
    },
    /// Draft wire version 2: asynchronous mailbox (see linkdrop-v2-spec.md).
    V2 {
        #[command(subcommand)]
        command: V2Command,
    },
}

#[derive(Debug, Subcommand)]
enum V2Command {
    /// Print a V2 contact bundle with one fresh one-time capability per server.
    Export {
        #[arg(long = "server")]
        servers: Vec<String>,
    },
    /// Import a V2 contact bundle; the first `v2 send` opens the chain.
    Import {
        bundle_file: PathBuf,
    },
    /// List V2 conversations.
    Contacts,
    /// Send a text message; consecutive sends never wait for the peer.
    Send {
        #[arg(long)]
        to: String,
        #[arg(long)]
        text: String,
    },
    /// Poll watched drops, acknowledge, and resend what was lost.
    Poll {
        /// Long-poll the lowest watched drop of each generation for this many seconds.
        #[arg(long)]
        wait: Option<u64>,
    },
    Inbox,
    History {
        #[arg(long)]
        contact: String,
    },
}

#[derive(Debug, Subcommand)]
enum ContactCommand {
    Export {
        #[arg(long = "server")]
        servers: Vec<String>,
    },
    Import {
        bundle_file: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum ContactsCommand {
    List,
}

#[derive(Debug, Subcommand)]
enum ServerCommand {
    Add {
        #[arg(long)]
        url: String,
    },
    List,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let app = LinkdropApp::new(cli.state_dir)?;

    match cli.command {
        Command::Init { name } => {
            app.init(&name)?;
            println!("initialized");
        }
        Command::Whoami => {
            println!("{}", format_whoami(&app.whoami()?));
        }
        Command::Contact { command } => match command {
            ContactCommand::Export { servers } => {
                let bundle = app.export_contact_bundle(&servers)?;
                println!("{}", serde_json::to_string_pretty(&bundle)?);
            }
            ContactCommand::Import { bundle_file } => {
                let contact = app.import_contact_bundle(&bundle_file)?;
                println!("{}", contact.contact_id);
            }
        },
        Command::Contacts { command } => match command {
            ContactsCommand::List => {
                println!("{}", format_contacts(&app.list_contacts()?));
            }
        },
        Command::Send { to, text, unsigned } => {
            let message = app.send_message(&to, &text, !unsigned)?;
            println!("{}", message.msg_id);
        }
        Command::Poll => {
            println!("{}", format_poll_summary(&app.poll()?));
        }
        Command::Inbox => {
            let contacts = app.list_contacts()?;
            println!("{}", format_messages(&app.inbox()?, &contacts));
        }
        Command::History { contact } => {
            let contacts = app.list_contacts()?;
            println!("{}", format_messages(&app.history(&contact)?, &contacts));
        }
        Command::Server { command } => match command {
            ServerCommand::Add { url } => {
                app.add_server(&url)?;
                println!("added");
            }
            ServerCommand::List => {
                println!("{}", format_servers(&app.list_servers()?));
            }
        },
        Command::V2 { command } => match command {
            V2Command::Export { servers } => {
                let bundle = app.v2_export_bundle(&servers)?;
                println!("{}", serde_json::to_string_pretty(&bundle)?);
            }
            V2Command::Import { bundle_file } => {
                let conversation = app.v2_import_bundle(&bundle_file)?;
                println!("{}", conversation.contact_id);
            }
            V2Command::Contacts => {
                println!("{}", format_v2_conversations(&app.v2_list_conversations()?));
            }
            V2Command::Send { to, text } => {
                let record = app.v2_send(&to, &text)?;
                println!("{} seq={}", record.msg_id, record.seq);
            }
            V2Command::Poll { wait } => {
                println!("{}", format_v2_poll_summary(&app.v2_poll(wait)?));
            }
            V2Command::Inbox => {
                let conversations = app.v2_list_conversations()?;
                println!("{}", format_v2_messages(&app.v2_inbox()?, &conversations));
            }
            V2Command::History { contact } => {
                let conversations = app.v2_list_conversations()?;
                println!(
                    "{}",
                    format_v2_messages(&app.v2_history(&contact)?, &conversations)
                );
            }
        },
    }

    Ok(())
}
