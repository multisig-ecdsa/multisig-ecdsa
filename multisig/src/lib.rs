pub mod message;
pub mod processor;
pub mod mta;
pub mod error;
mod state;
mod proof;
pub mod zero_knowledge;

pub type MultiSignature = processor::MultisigProcessor<state::MultisigStatePhase1>;