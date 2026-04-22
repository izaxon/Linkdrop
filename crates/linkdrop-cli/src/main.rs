use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use linkdrop_cli::{
    LinkdropApp, format_contacts, format_messages, format_poll_summary, format_whoami,
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
    },
    Poll,
    Inbox,
    History {
        #[arg(long)]
        contact: String,
    },
}

#[derive(Debug, Subcommand)]
enum ContactCommand {
    Export {
        #[arg(long = "server", required = true)]
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
        Command::Send { to, text } => {
            let message = app.send_message(&to, &text)?;
            println!("{}", message.msg_id);
        }
        Command::Poll => {
            println!("{}", format_poll_summary(&app.poll()?));
        }
        Command::Inbox => {
            println!("{}", format_messages(&app.inbox()?));
        }
        Command::History { contact } => {
            println!("{}", format_messages(&app.history(&contact)?));
        }
    }

    Ok(())
}
