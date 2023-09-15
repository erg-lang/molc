pub mod messages;

use std::collections::HashMap;
use std::fs::File;
use std::io::{stdout, Read, Write};
use std::path::Path;
use std::sync::mpsc::{Receiver, Sender};

use lsp_types::notification::Notification;
use lsp_types::request::Request;
use lsp_types::{
    ClientCapabilities, CodeActionClientCapabilities, CompletionClientCapabilities,
    CompletionContext, CompletionParams, CompletionResponse, CompletionTriggerKind,
    DidChangeTextDocumentParams, DidOpenTextDocumentParams, DocumentLinkClientCapabilities,
    DocumentSymbolClientCapabilities, DocumentSymbolParams, DocumentSymbolResponse,
    DynamicRegistrationClientCapabilities, FoldingRange, FoldingRangeClientCapabilities,
    FoldingRangeParams, GotoCapability, GotoDefinitionParams, GotoDefinitionResponse, Hover,
    HoverClientCapabilities, HoverParams, InitializeParams, InitializeResult, InitializedParams,
    InlayHint, InlayHintClientCapabilities, InlayHintParams, Location, MarkupKind, Position,
    PublishDiagnosticsClientCapabilities, Range, ReferenceContext, ReferenceParams,
    RenameClientCapabilities, RenameParams, SelectionRangeClientCapabilities,
    SemanticTokensClientCapabilities, ServerCapabilities, SignatureHelp,
    SignatureHelpClientCapabilities, SignatureHelpContext, SignatureHelpParams,
    SignatureHelpTriggerKind, TextDocumentClientCapabilities, TextDocumentContentChangeEvent,
    TextDocumentIdentifier, TextDocumentItem, TextDocumentPositionParams,
    TextDocumentSyncClientCapabilities, Url, VersionedTextDocumentIdentifier, WorkspaceEdit, DidSaveTextDocumentParams,
};
use serde::de::Deserialize;
use serde::Serialize;
use serde_json::{json, Value};

use crate::messages::{ErrorMessage, LogMessage, ShowMessage};

fn safe_yield() {
    std::thread::yield_now();
    std::thread::sleep(std::time::Duration::from_millis(10));
}

/// Adds a character at the given position.
pub fn add_char(line: u32, character: u32, text: &str) -> TextDocumentContentChangeEvent {
    TextDocumentContentChangeEvent {
        range: Some(Range {
            start: Position { line, character },
            end: Position { line, character },
        }),
        range_length: None,
        text: text.to_string(),
    }
}

/// Changes the text at the given position.
pub fn change_text(line: u32, character: u32, text: &str) -> TextDocumentContentChangeEvent {
    TextDocumentContentChangeEvent {
        range: Some(Range {
            start: Position { line, character },
            end: Position {
                line,
                character: character + text.chars().count() as u32,
            },
        }),
        range_length: None,
        text: text.to_string(),
    }
}

/// Deletes the text at the given range.
pub fn delete_text(line: u32, character: u32, len: u32) -> TextDocumentContentChangeEvent {
    TextDocumentContentChangeEvent {
        range: Some(Range {
            start: Position { line, character },
            end: Position {
                line,
                character: character + len,
            },
        }),
        range_length: Some(len),
        text: "".to_string(),
    }
}

/// Deletes the line at the given index.
pub fn delete_line(line: u32) -> TextDocumentContentChangeEvent {
    TextDocumentContentChangeEvent {
        range: Some(Range {
            start: Position { line, character: 0 },
            end: Position {
                line: line + 1,
                character: 0,
            },
        }),
        range_length: None,
        text: "".to_string(),
    }
}

/// Indicates an absolute position in the document.
pub fn abs_pos(uri: Url, line: u32, col: u32) -> TextDocumentPositionParams {
    TextDocumentPositionParams {
        text_document: TextDocumentIdentifier::new(uri),
        position: Position {
            line,
            character: col,
        },
    }
}

/// Indicates a range of one line.
pub fn oneline_range(line: u32, from: u32, to: u32) -> Range {
    Range {
        start: Position {
            line,
            character: from,
        },
        end: Position {
            line,
            character: to,
        },
    }
}

/// Parses a sequence of LSP messages and returns them as a vector of `Value`s.
pub fn parse_msgs(_input: &str) -> Vec<Value> {
    let mut input = _input;
    let mut msgs = Vec::new();
    loop {
        if input.starts_with("Content-Length: ") {
            let idx = "Content-Length: ".len();
            input = &input[idx..];
        } else {
            break;
        }
        let dights = input.find("\r\n").unwrap();
        let len = input[..dights].parse::<usize>().unwrap();
        let idx = dights + "\r\n\r\n".len();
        input = &input[idx..];
        let msg = &input
            .get(..len)
            .unwrap_or_else(|| panic!("len: {len}, input: `{input}` -> _input: `{_input}`"));
        input = &input[len..];
        msgs.push(serde_json::from_str(msg).unwrap());
    }
    msgs
}

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// Servers implementing this must return output with the `send_*` method provided by this trait.
pub trait RedirectableStdout {
    fn sender(&self) -> Option<&Sender<Value>>;

    fn send_stdout<T: ?Sized + Serialize>(&self, message: &T) -> Result<()> {
        if let Some(sender) = self.sender() {
            sender.send(serde_json::to_value(message)?)?;
        } else {
            let msg = serde_json::to_string(message)?;
            let mut stdout = stdout().lock();
            write!(stdout, "Content-Length: {}\r\n\r\n{}", msg.len(), msg)?;
            stdout.flush()?;
        }
        Ok(())
    }

    fn send_log<S: Into<String>>(&self, msg: S) -> Result<()> {
        if cfg!(debug_assertions) || cfg!(feature = "debug") {
            self.send_stdout(&LogMessage::new(msg))
        } else {
            Ok(())
        }
    }

    #[allow(unused)]
    fn send_info<S: Into<String>>(&self, msg: S) -> Result<()> {
        self.send_stdout(&ShowMessage::info(msg))
    }

    fn send_error_info<S: Into<String>>(&self, msg: S) -> Result<()> {
        self.send_stdout(&ShowMessage::error(msg))
    }

    fn send_error<S: Into<String>>(&self, id: Option<i64>, code: i64, msg: S) -> Result<()> {
        self.send_stdout(&ErrorMessage::new(
            id,
            json!({ "code": code, "message": msg.into() }),
        ))
    }

    fn send_invalid_req_error(&self) -> Result<()> {
        self.send_error(None, -32601, "received an invalid request")
    }
}

pub trait LangServer {
    /// Receive and process a message from the client. Output should be returned to the channel.
    fn dispatch(&mut self, msg: impl Into<Value>) -> Result<()>;
}

pub struct FakeClient<LS: LangServer> {
    pub server: LS,
    receiver: Receiver<Value>,
    pub client_capas: ClientCapabilities,
    pub server_capas: Option<ServerCapabilities>,
    /// Stores all messages received from the server.
    pub responses: Vec<Value>,
    #[allow(clippy::complexity)]
    handlers: HashMap<String, Box<dyn Fn(&Value, &mut LS) -> Result<()>>>,
    ver: i32,
    req_id: i64,
}

impl<LS: LangServer> FakeClient<LS> {
    /// The server should send responses to the channel at least during testing.
    pub fn new(server: LS, receiver: Receiver<Value>) -> Self {
        FakeClient {
            receiver,
            responses: Vec::new(),
            ver: 0,
            req_id: 0,
            client_capas: ClientCapabilities {
                text_document: Some(TextDocumentClientCapabilities {
                    synchronization: Some(TextDocumentSyncClientCapabilities {
                        did_save: Some(true),
                        ..Default::default()
                    }),
                    completion: Some(CompletionClientCapabilities {
                        completion_item: Some(Default::default()),
                        completion_item_kind: Some(Default::default()),
                        ..Default::default()
                    }),
                    hover: Some(HoverClientCapabilities {
                        content_format: Some(vec![MarkupKind::PlainText]),
                        ..Default::default()
                    }),
                    signature_help: Some(SignatureHelpClientCapabilities {
                        signature_information: Some(Default::default()),
                        ..Default::default()
                    }),
                    references: Some(DynamicRegistrationClientCapabilities::default()),
                    document_highlight: Some(DynamicRegistrationClientCapabilities::default()),
                    document_symbol: Some(DocumentSymbolClientCapabilities {
                        ..Default::default()
                    }),
                    formatting: Some(DynamicRegistrationClientCapabilities::default()),
                    range_formatting: Some(DynamicRegistrationClientCapabilities::default()),
                    on_type_formatting: Some(DynamicRegistrationClientCapabilities::default()),
                    declaration: Some(GotoCapability {
                        link_support: Some(true),
                        ..Default::default()
                    }),
                    definition: Some(GotoCapability {
                        link_support: Some(true),
                        ..Default::default()
                    }),
                    type_definition: Some(GotoCapability {
                        link_support: Some(true),
                        ..Default::default()
                    }),
                    implementation: Some(GotoCapability {
                        link_support: Some(true),
                        ..Default::default()
                    }),
                    code_action: Some(CodeActionClientCapabilities {
                        data_support: Some(true),
                        ..Default::default()
                    }),
                    code_lens: Some(DynamicRegistrationClientCapabilities::default()),
                    document_link: Some(DocumentLinkClientCapabilities {
                        tooltip_support: Some(true),
                        dynamic_registration: Some(false),
                    }),
                    color_provider: Some(DynamicRegistrationClientCapabilities::default()),
                    rename: Some(RenameClientCapabilities {
                        prepare_support: Some(true),
                        ..Default::default()
                    }),
                    publish_diagnostics: Some(PublishDiagnosticsClientCapabilities {
                        related_information: Some(true),
                        ..Default::default()
                    }),
                    folding_range: Some(FoldingRangeClientCapabilities {
                        ..Default::default()
                    }),
                    selection_range: Some(SelectionRangeClientCapabilities {
                        ..Default::default()
                    }),
                    linked_editing_range: Some(DynamicRegistrationClientCapabilities::default()),
                    call_hierarchy: Some(DynamicRegistrationClientCapabilities::default()),
                    semantic_tokens: Some(SemanticTokensClientCapabilities {
                        ..Default::default()
                    }),
                    moniker: Some(DynamicRegistrationClientCapabilities::default()),
                    inlay_hint: Some(InlayHintClientCapabilities {
                        ..Default::default()
                    }),
                }),
                ..Default::default()
            },
            server_capas: None,
            handlers: HashMap::new(),
            server,
        }
    }

    /// Adds a handler for the request/notification with the given method name.
    /// When the client receives a request/notification for the specified method, it executes the handler.
    pub fn add_handler(
        &mut self,
        method_name: impl Into<String>,
        handler: impl Fn(&Value, &mut LS) -> Result<()> + 'static,
    ) {
        self.handlers
            .insert(method_name.into(), Box::new(handler));
    }

    /// Removes the handler for the request/notification with the given method name.
    pub fn remove_handler(&mut self, method_name: &str) {
        self.handlers.remove(method_name);
    }

    pub fn enable_log_display(&mut self) {
        self.add_handler("window/logMessage", |msg, _| {
            let msg = LogMessage::deserialize(msg.clone())?;
            println!("[LOG]: {}", &msg.params["message"]);
            Ok(())
        });
    }

    /// Waits for `n` messages to be received.
    /// When a request is received, the registered handler will be executed.
    pub fn wait_messages(&mut self, n: usize) -> Result<()> {
        for _ in 0..n {
            if let Ok(msg) = self.receiver.recv() {
                if msg.get("method").is_some() {
                    self.handle_server_message(&msg);
                }
                self.responses.push(msg);
            }
        }
        Ok(())
    }

    /// Waits for a response to the request, where its `id` is expected to be that of `req_id`,
    /// and `req_id` will be incremented if the response is successfully received.
    /// When a request is received, the registered handler will be executed.
    fn wait_for<R>(&mut self) -> Result<R>
    where
        R: Deserialize<'static>,
    {
        loop {
            if let Ok(msg) = self.receiver.recv() {
                if msg.get("method").is_some() {
                    self.handle_server_message(&msg);
                }
                self.responses.push(msg);
                let msg = self.responses.last().unwrap();
                if msg.get("id").is_some_and(|val| val == self.req_id) {
                    if let Some(result) = msg
                        .get("result")
                        .cloned()
                        .and_then(|res| R::deserialize(res).ok())
                    {
                        self.req_id += 1;
                        return Ok(result);
                    }
                }
            }
            safe_yield();
        }
    }

    fn handle_server_message(&mut self, msg: &Value) {
        if let Some(method) = msg.get("method").and_then(|val| val.as_str()) {
            if let Some(handler) = self.handlers.get(method) {
                if let Err(err) = handler(msg, &mut self.server) {
                    eprintln!("error: {:?}", err);
                }
            }
        }
    }

    /// Send a request to the server.
    pub fn request<R: Request>(&mut self, params: R::Params) -> Result<R::Result> {
        let msg = json!({
            "jsonrpc": "2.0",
            "id": self.req_id,
            "method": R::METHOD,
            "params": params,
        });
        self.server.dispatch(msg)?;
        self.wait_for::<R::Result>()
    }

    /// Send a notification to the server.
    pub fn notify<N: Notification>(&mut self, params: N::Params) -> Result<()> {
        let msg = json!({
            "jsonrpc": "2.0",
            "method": N::METHOD,
            "params": params,
        });
        self.server.dispatch(msg)?;
        Ok(())
    }

    /// Send an `initialize` request to the server.
    /// This will set the server capabilities
    pub fn request_initialize(&mut self) -> Result<InitializeResult> {
        let params = InitializeParams {
            capabilities: self.client_capas.clone(),
            ..Default::default()
        };
        let msg = json!({
            "jsonrpc": "2.0",
            "id": self.req_id,
            "method": "initialize",
            "params": params,
        });
        self.server.dispatch(msg)?;
        let res = self.wait_for::<InitializeResult>()?;
        self.server_capas = Some(res.capabilities.clone());
        Ok(res)
    }

    /// Send an `initialized` notification to the server.
    pub fn notify_initialized(&mut self) -> Result<()> {
        let params = InitializedParams {};
        let msg = json!({
            "jsonrpc": "2.0",
            "method": "initialized",
            "params": params,
        });
        self.server.dispatch(msg)?;
        Ok(())
    }

    /// Send an `exit` notification to the server.
    pub fn notify_exit(&mut self) -> Result<()> {
        let msg = json!({
            "jsonrpc": "2.0",
            "method": "exit",
            "params": null,
        });
        self.server.dispatch(msg)?;
        Ok(())
    }

    /// Send a `textDocument/didOpen` notification to the server.
    pub fn notify_open(&mut self, file: &str) -> Result<()> {
        let uri = Url::from_file_path(Path::new(file).canonicalize().unwrap()).unwrap();
        let mut text = String::new();
        File::open(file).unwrap().read_to_string(&mut text)?;
        let params = DidOpenTextDocumentParams {
            text_document: TextDocumentItem::new(uri, "erg".to_string(), self.ver, text),
        };
        self.ver += 1;
        let msg = json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didOpen",
            "params": params,
        });
        self.server.dispatch(msg)?;
        Ok(())
    }

    /// Send a `textDocument/didChange` notification to the server.
    pub fn notify_change(
        &mut self,
        uri: Url,
        change: TextDocumentContentChangeEvent,
    ) -> Result<()> {
        let params = DidChangeTextDocumentParams {
            text_document: VersionedTextDocumentIdentifier::new(uri.clone(), self.ver),
            content_changes: vec![change],
        };
        self.ver += 1;
        let msg = json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didChange",
            "params": params,
        });
        self.server.dispatch(msg)?;
        Ok(())
    }

    /// Send a `textDocument/didSave` notification to the server.
    pub fn notify_save(&mut self, uri: Url) -> Result<()> {
        let params = DidSaveTextDocumentParams {
            text_document: TextDocumentIdentifier::new(uri),
            text: None,
        };
        let msg = json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didSave",
            "params": params,
        });
        self.server.dispatch(msg)?;
        Ok(())
    }

    /// Send a `textDocument/didClose` notification to the server.
    pub fn notify_close(&mut self, uri: Url) -> Result<()> {
        let params = TextDocumentIdentifier::new(uri);
        let msg = json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didClose",
            "params": params,
        });
        self.server.dispatch(msg)?;
        Ok(())
    }

    fn is_trigger_char(&self, character: &str) -> bool {
        self.server_capas.as_ref().is_some_and(|cap| {
            cap.completion_provider.as_ref().is_some_and(|comp| {
                comp.trigger_characters
                    .as_ref()
                    .is_some_and(|chars| chars.iter().any(|c| c == character))
            })
        })
    }

    /// Send a `shutdown` request to the server.
    pub fn request_shutdown(&mut self) -> Result<()> {
        let msg = json!({
            "jsonrpc": "2.0",
            "id": self.req_id,
            "method": "shutdown",
        });
        self.server.dispatch(msg)?;
        self.wait_for::<()>()
    }

    /// Send a `textDocument/completion` request to the server.
    pub fn request_completion(
        &mut self,
        uri: Url,
        line: u32,
        col: u32,
        character: &str,
    ) -> Result<Option<CompletionResponse>> {
        let text_document_position = abs_pos(uri, line, col);
        let trigger_kind = if self.is_trigger_char(character) {
            CompletionTriggerKind::TRIGGER_CHARACTER
        } else {
            CompletionTriggerKind::INVOKED
        };
        let trigger_character = self
            .is_trigger_char(character)
            .then_some(character.to_string());
        let context = Some(CompletionContext {
            trigger_kind,
            trigger_character,
        });
        let params = CompletionParams {
            text_document_position,
            context,
            work_done_progress_params: Default::default(),
            partial_result_params: Default::default(),
        };
        let msg = json!({
            "jsonrpc": "2.0",
            "id": self.req_id,
            "method": "textDocument/completion",
            "params": params,
        });
        self.server.dispatch(msg)?;
        self.wait_for::<Option<CompletionResponse>>()
    }

    /// Send a `textDocument/rename` request to the server.
    pub fn request_rename(
        &mut self,
        uri: Url,
        line: u32,
        col: u32,
        new_name: &str,
    ) -> Result<Option<WorkspaceEdit>> {
        let text_document_position = abs_pos(uri, line, col);
        let params = RenameParams {
            text_document_position,
            new_name: new_name.to_string(),
            work_done_progress_params: Default::default(),
        };
        let msg = json!({
            "jsonrpc": "2.0",
            "id": self.req_id,
            "method": "textDocument/rename",
            "params": params,
        });
        self.server.dispatch(msg)?;
        self.wait_for::<Option<WorkspaceEdit>>()
    }

    /// Send a `textDocument/signatureHelp` request to the server.
    pub fn request_signature_help(
        &mut self,
        uri: Url,
        line: u32,
        col: u32,
        character: &str,
    ) -> Result<Option<SignatureHelp>> {
        let text_document_position_params = abs_pos(uri, line, col);
        let context = SignatureHelpContext {
            trigger_kind: SignatureHelpTriggerKind::TRIGGER_CHARACTER,
            trigger_character: Some(character.to_string()),
            is_retrigger: false,
            active_signature_help: None,
        };
        let params = SignatureHelpParams {
            text_document_position_params,
            context: Some(context),
            work_done_progress_params: Default::default(),
        };
        let msg = json!({
            "jsonrpc": "2.0",
            "id": self.req_id,
            "method": "textDocument/signatureHelp",
            "params": params,
        });
        self.server.dispatch(msg)?;
        self.wait_for::<Option<SignatureHelp>>()
    }

    /// Send a `textDocument/hover` request to the server.
    pub fn request_hover(&mut self, uri: Url, line: u32, col: u32) -> Result<Option<Hover>> {
        let params = HoverParams {
            text_document_position_params: abs_pos(uri, line, col),
            work_done_progress_params: Default::default(),
        };
        let msg = json!({
            "jsonrpc": "2.0",
            "id": self.req_id,
            "method": "textDocument/hover",
            "params": params,
        });
        self.server.dispatch(msg)?;
        self.wait_for::<Option<Hover>>()
    }

    /// Send a `textDocument/references` request to the server.
    pub fn request_references(
        &mut self,
        uri: Url,
        line: u32,
        col: u32,
    ) -> Result<Option<Vec<Location>>> {
        let context = ReferenceContext {
            include_declaration: false,
        };
        let params = ReferenceParams {
            text_document_position: abs_pos(uri, line, col),
            context,
            work_done_progress_params: Default::default(),
            partial_result_params: Default::default(),
        };
        let msg = json!({
            "jsonrpc": "2.0",
            "id": self.req_id,
            "method": "textDocument/references",
            "params": params,
        });
        self.server.dispatch(msg)?;
        self.wait_for::<Option<Vec<Location>>>()
    }

    /// Send a `textDocument/definition` request to the server.
    pub fn request_goto_definition(
        &mut self,
        uri: Url,
        line: u32,
        col: u32,
    ) -> Result<Option<GotoDefinitionResponse>> {
        let params = GotoDefinitionParams {
            text_document_position_params: abs_pos(uri, line, col),
            work_done_progress_params: Default::default(),
            partial_result_params: Default::default(),
        };
        let msg = json!({
            "jsonrpc": "2.0",
            "id": self.req_id,
            "method": "textDocument/definition",
            "params": params,
        });
        self.server.dispatch(msg)?;
        self.wait_for::<Option<GotoDefinitionResponse>>()
    }

    /// Send a `textDocument/foldingRange` request to the server.
    pub fn request_folding_range(&mut self, uri: Url) -> Result<Option<Vec<FoldingRange>>> {
        let params = FoldingRangeParams {
            text_document: TextDocumentIdentifier::new(uri),
            work_done_progress_params: Default::default(),
            partial_result_params: Default::default(),
        };
        let msg = json!({
            "jsonrpc": "2.0",
            "id": self.req_id,
            "method": "textDocument/foldingRange",
            "params": params,
        });
        self.server.dispatch(msg)?;
        self.wait_for::<Option<Vec<FoldingRange>>>()
    }

    /// Send a `textDocument/documentSymbol` request to the server.
    pub fn request_document_symbols(&mut self, uri: Url) -> Result<Option<DocumentSymbolResponse>> {
        let params = DocumentSymbolParams {
            text_document: TextDocumentIdentifier::new(uri),
            work_done_progress_params: Default::default(),
            partial_result_params: Default::default(),
        };
        let msg = json!({
            "jsonrpc": "2.0",
            "id": self.req_id,
            "method": "textDocument/documentSymbol",
            "params": params,
        });
        self.server.dispatch(msg)?;
        self.wait_for::<Option<DocumentSymbolResponse>>()
    }

    /// Send a `textDocument/inlayHint` request to the server.
    pub fn request_inlay_hint(&mut self, uri: Url) -> Result<Option<Vec<InlayHint>>> {
        let params = InlayHintParams {
            text_document: TextDocumentIdentifier::new(uri),
            range: Range {
                start: Position {
                    line: 0,
                    character: 0,
                },
                end: Position {
                    line: u32::MAX,
                    character: u32::MAX,
                },
            },
            work_done_progress_params: Default::default(),
        };
        let msg = json!({
            "jsonrpc": "2.0",
            "id": self.req_id,
            "method": "textDocument/inlayHint",
            "params": params,
        });
        self.server.dispatch(msg)?;
        self.wait_for::<Option<Vec<InlayHint>>>()
    }
}
