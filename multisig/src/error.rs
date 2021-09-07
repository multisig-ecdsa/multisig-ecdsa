use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvalidDecommitment;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvalidProof;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigAbort;
