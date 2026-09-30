use prost::Message;
use prost_types::{DescriptorProto, EnumDescriptorProto, FileDescriptorProto, FileDescriptorSet};
use qk_openshell::FILE_DESCRIPTOR_SET;

fn descriptor() -> FileDescriptorSet {
    FileDescriptorSet::decode(FILE_DESCRIPTOR_SET).expect("generated descriptor set")
}

fn file<'a>(set: &'a FileDescriptorSet, name: &str) -> &'a FileDescriptorProto {
    set.file
        .iter()
        .find(|file| file.name.as_deref() == Some(name))
        .unwrap_or_else(|| panic!("descriptor file {name} is missing"))
}

fn message<'a>(file: &'a FileDescriptorProto, name: &str) -> &'a DescriptorProto {
    file.message_type
        .iter()
        .find(|message| message.name.as_deref() == Some(name))
        .unwrap_or_else(|| panic!("message {name} is missing"))
}

fn enum_type<'a>(file: &'a FileDescriptorProto, name: &str) -> &'a EnumDescriptorProto {
    file.enum_type
        .iter()
        .find(|enum_type| enum_type.name.as_deref() == Some(name))
        .unwrap_or_else(|| panic!("enum {name} is missing"))
}

fn field_numbers(message: &DescriptorProto) -> Vec<(&str, i32)> {
    message
        .field
        .iter()
        .map(|field| {
            (
                field.name.as_deref().expect("field name"),
                field.number.expect("field number"),
            )
        })
        .collect()
}

fn enum_values(enum_type: &EnumDescriptorProto) -> Vec<(&str, i32)> {
    enum_type
        .value
        .iter()
        .map(|value| {
            (
                value.name.as_deref().expect("enum value name"),
                value.number.expect("enum value number"),
            )
        })
        .collect()
}

#[test]
fn supervisor_services_streaming_and_wire_field_numbers_match_open_shell() {
    let set = descriptor();
    let middleware = file(&set, "supervisor_middleware.proto");
    assert_eq!(
        middleware.package.as_deref(),
        Some("openshell.middleware.v1")
    );

    let supervisor = middleware
        .service
        .iter()
        .find(|service| service.name.as_deref() == Some("SupervisorMiddleware"))
        .expect("SupervisorMiddleware service");
    let method_names: Vec<_> = supervisor
        .method
        .iter()
        .map(|method| method.name.as_deref().expect("method name"))
        .collect();
    assert_eq!(
        method_names,
        [
            "Describe",
            "ValidateConfig",
            "EvaluateHttpRequest",
            "EvaluateWebSocketSession"
        ]
    );
    let websocket = supervisor
        .method
        .iter()
        .find(|method| method.name.as_deref() == Some("EvaluateWebSocketSession"))
        .expect("WebSocket RPC");
    assert_eq!(websocket.client_streaming, Some(true));
    assert_eq!(websocket.server_streaming, Some(true));

    let response_service = middleware
        .service
        .iter()
        .find(|service| service.name.as_deref() == Some("HttpResponsePreReturn"))
        .expect("response service descriptor");
    assert_eq!(response_service.method.len(), 1);
    assert_eq!(response_service.method[0].name.as_deref(), Some("Evaluate"));
    assert_eq!(response_service.method[0].client_streaming, Some(true));
    assert_eq!(response_service.method[0].server_streaming, Some(true));

    assert_eq!(
        field_numbers(message(middleware, "MiddlewareManifest")),
        [
            ("name", 1),
            ("service_version", 2),
            ("bindings", 3),
            ("expected_audience", 4),
            ("extension", 5)
        ]
    );
    assert_eq!(
        field_numbers(message(middleware, "HttpRequestEvaluation")),
        [
            ("phase", 1),
            ("context", 2),
            ("config", 3),
            ("target", 4),
            ("headers", 5),
            ("body", 6),
            ("middleware_name", 7)
        ]
    );
    assert_eq!(
        enum_values(enum_type(middleware, "Decision")),
        [
            ("DECISION_UNSPECIFIED", 0),
            ("DECISION_ALLOW", 1),
            ("DECISION_DENY", 2)
        ]
    );
}

#[test]
fn peer_metadata_schema_is_present_and_compatible() {
    let set = descriptor();
    let extension = file(&set, "extension.proto");
    assert_eq!(extension.package.as_deref(), Some("openshell.extension.v1"));
    assert_eq!(
        field_numbers(message(extension, "ProtocolVersion")),
        [("major", 1), ("minor", 2)]
    );
    assert_eq!(
        field_numbers(message(extension, "PeerMetadata")),
        [
            ("protocol_version", 1),
            ("implementation_name", 2),
            ("implementation_version", 3),
            ("supported_capabilities", 4),
            ("required_capabilities", 5)
        ]
    );
}
