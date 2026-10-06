// SPDX-License-Identifier: MPL-2.0
// Portions of Veilid, Copyright Veilid contributors.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. https://mozilla.org/MPL/2.0/
// Upstream dd8e2cdd72b5bf817172ac31c20872b168c5c8fc:
// rpc_processor/coders/operations/operation_app_{call_q,call_a,message}.rs.
//! Original application operations. Node signatures confer no member authority.
use super::*;

/// Original application payload and operation kind, after signature verification.
/// Payload authentication/authorization belongs to its application owner.
#[derive(PartialEq, Eq)]
pub enum Application {
    /// AppCallQ; its response must be AppCallA with the same operation ID.
    Call(Vec<u8>),
    /// AppCallA; correlate through the originating question before delivery.
    Reply(Vec<u8>),
    /// AppMessage; no acknowledgment is implied.
    Message(Vec<u8>),
}
impl std::fmt::Debug for Application {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Call(_) => "Application::Call([redacted])",
            Self::Reply(_) => "Application::Reply([redacted])",
            Self::Message(_) => "Application::Message([redacted])",
        })
    }
}

/// Original authenticated operation category, never inferred from raw prefixes
/// or a failed application parse. Body validation remains in its typed decoder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperationKind {
    ApplicationCall,
    ApplicationReply,
    ApplicationMessage,
    RecordsQuestion,
    RecordsAnswer,
    RecordsStatement,
}

/// Read only original discriminants from an already authenticated operation.
/// Unsupported/unknown variants refuse; no parser fallback can turn malformed
/// Records into application traffic or vice versa.
pub fn operation_kind(operation: &SignedOperation) -> Result<OperationKind, Error> {
    let message = read(operation.operation())?;
    let root = message
        .get_root::<wire::operation::Reader>()
        .map_err(|_| Error::Encoding)?;
    match root.get_kind().which().map_err(|_| Error::Encoding)? {
        wire::operation::kind::Question(question) => {
            use wire::question::detail::*;
            match question
                .map_err(|_| Error::Encoding)?
                .get_detail()
                .which()
                .map_err(|_| Error::Encoding)?
            {
                AppCallQ(value) => {
                    value.map_err(|_| Error::Encoding)?;
                    Ok(OperationKind::ApplicationCall)
                }
                FindNodeQ(value) => {
                    value.map_err(|_| Error::Encoding)?;
                    Ok(OperationKind::RecordsQuestion)
                }
                GetValueQ(value) => {
                    value.map_err(|_| Error::Encoding)?;
                    Ok(OperationKind::RecordsQuestion)
                }
                SetValueQ(value) => {
                    value.map_err(|_| Error::Encoding)?;
                    Ok(OperationKind::RecordsQuestion)
                }
                WatchValueQ(value) => {
                    value.map_err(|_| Error::Encoding)?;
                    Ok(OperationKind::RecordsQuestion)
                }
                InspectValueQ(value) => {
                    value.map_err(|_| Error::Encoding)?;
                    Ok(OperationKind::RecordsQuestion)
                }
                _ => Err(Error::Encoding),
            }
        }
        wire::operation::kind::Answer(answer) => {
            use wire::answer::detail::*;
            match answer
                .map_err(|_| Error::Encoding)?
                .get_detail()
                .which()
                .map_err(|_| Error::Encoding)?
            {
                AppCallA(value) => {
                    value.map_err(|_| Error::Encoding)?;
                    Ok(OperationKind::ApplicationReply)
                }
                FindNodeA(value) => {
                    value.map_err(|_| Error::Encoding)?;
                    Ok(OperationKind::RecordsAnswer)
                }
                GetValueA(value) => {
                    value.map_err(|_| Error::Encoding)?;
                    Ok(OperationKind::RecordsAnswer)
                }
                SetValueA(value) => {
                    value.map_err(|_| Error::Encoding)?;
                    Ok(OperationKind::RecordsAnswer)
                }
                WatchValueA(value) => {
                    value.map_err(|_| Error::Encoding)?;
                    Ok(OperationKind::RecordsAnswer)
                }
                InspectValueA(value) => {
                    value.map_err(|_| Error::Encoding)?;
                    Ok(OperationKind::RecordsAnswer)
                }
                _ => Err(Error::Encoding),
            }
        }
        wire::operation::kind::Statement(statement) => {
            use wire::statement::detail::*;
            match statement
                .map_err(|_| Error::Encoding)?
                .get_detail()
                .which()
                .map_err(|_| Error::Encoding)?
            {
                AppMessage(value) => {
                    value.map_err(|_| Error::Encoding)?;
                    Ok(OperationKind::ApplicationMessage)
                }
                ValueChanged(value) => {
                    value.map_err(|_| Error::Encoding)?;
                    Ok(OperationKind::RecordsStatement)
                }
                _ => Err(Error::Encoding),
            }
        }
    }
}

/// Decode only an authenticated original application operation, preserving its ID.
/// The caller verifies the expected signer/destination and the outer ENV0 first.
/// Every other variant, including Records/discovery, returns `Error::Encoding`.
/// Errors are refusals, never an instruction to try another protocol parser.
pub fn application(operation: &SignedOperation) -> Result<(u64, Application), Error> {
    decode(operation.operation())
}

fn decode(encoded: &[u8]) -> Result<(u64, Application), Error> {
    let message = read(encoded)?;
    let operation = message
        .get_root::<wire::operation::Reader>()
        .map_err(|_| Error::Encoding)?;
    let application = match operation.get_kind().which().map_err(|_| Error::Encoding)? {
        wire::operation::kind::Question(question) => {
            let question = question.map_err(|_| Error::Encoding)?;
            if !matches!(
                question
                    .get_respond_to()
                    .which()
                    .map_err(|_| Error::Encoding)?,
                wire::question::respond_to::Sender(())
            ) {
                return Err(Error::Encoding);
            }
            let wire::question::detail::AppCallQ(call) =
                question.get_detail().which().map_err(|_| Error::Encoding)?
            else {
                return Err(Error::Encoding);
            };
            Application::Call(
                call.map_err(|_| Error::Encoding)?
                    .get_message()
                    .map_err(|_| Error::Encoding)?
                    .to_vec(),
            )
        }
        wire::operation::kind::Answer(answer) => {
            let wire::answer::detail::AppCallA(reply) = answer
                .map_err(|_| Error::Encoding)?
                .get_detail()
                .which()
                .map_err(|_| Error::Encoding)?
            else {
                return Err(Error::Encoding);
            };
            Application::Reply(
                reply
                    .map_err(|_| Error::Encoding)?
                    .get_message()
                    .map_err(|_| Error::Encoding)?
                    .to_vec(),
            )
        }
        wire::operation::kind::Statement(statement) => {
            let wire::statement::detail::AppMessage(message) = statement
                .map_err(|_| Error::Encoding)?
                .get_detail()
                .which()
                .map_err(|_| Error::Encoding)?
            else {
                return Err(Error::Encoding);
            };
            Application::Message(
                message
                    .map_err(|_| Error::Encoding)?
                    .get_message()
                    .map_err(|_| Error::Encoding)?
                    .to_vec(),
            )
        }
    };
    Ok((operation.get_op_id(), application))
}

// Refuse before allocating a builder; bytes() also enforces encoding overhead.
fn check_payload(payload: &[u8]) -> Result<(), Error> {
    if payload.len() > MAX_RPC_BYTES {
        return Err(Error::ValueTooLarge);
    }
    Ok(())
}

impl Question {
    /// Encode original AppCallQ with a random ID and response to the sender.
    /// Existing `sign` binds it to its exact destination inside the key owner.
    pub fn application(payload: &[u8]) -> Result<Self, Error> {
        check_payload(payload)?;
        let id = random_id()?;
        let mut message = Builder::new_default();
        let mut operation = message.init_root::<wire::operation::Builder>();
        operation.set_op_id(id);
        let mut question = operation.get_kind().init_question();
        question.reborrow().get_respond_to().set_sender(());
        question.get_detail().init_app_call_q().set_message(payload);
        Ok(Self {
            id,
            bytes: bytes(message)?,
        })
    }

    /// Decode an authenticated AppCallA for this exact original AppCallQ and ID.
    /// Expected responder and destination verification precedes this correlation.
    pub fn application_answer(&self, response: &SignedOperation) -> Result<Vec<u8>, Error> {
        let (original_id, Application::Call(_)) = decode(&self.bytes)? else {
            return Err(Error::Encoding);
        };
        let (id, Application::Reply(payload)) = application(response)? else {
            return Err(Error::Encoding);
        };
        if original_id != self.id || id != self.id {
            return Err(Error::Encoding);
        }
        Ok(payload)
    }
}

impl Answer {
    /// Encode original AppCallA, bound to an authenticated AppCallQ's ID and type.
    pub fn application(question: &SignedOperation, payload: &[u8]) -> Result<Self, Error> {
        check_payload(payload)?;
        let (id, Application::Call(_)) = application(question)? else {
            return Err(Error::Encoding);
        };
        let mut message = Builder::new_default();
        let mut operation = message.init_root::<wire::operation::Builder>();
        operation.set_op_id(id);
        operation
            .get_kind()
            .init_answer()
            .get_detail()
            .init_app_call_a()
            .set_message(payload);
        Ok(Self(bytes(message)?))
    }
}

impl Statement {
    /// Encode original AppMessage with a random ID; existing signing stays intact.
    pub fn application(payload: &[u8]) -> Result<Self, Error> {
        check_payload(payload)?;
        let mut message = Builder::new_default();
        let mut operation = message.init_root::<wire::operation::Builder>();
        operation.set_op_id(random_id()?);
        operation
            .get_kind()
            .init_statement()
            .get_detail()
            .init_app_message()
            .set_message(payload);
        Ok(Self(bytes(message)?))
    }
}
