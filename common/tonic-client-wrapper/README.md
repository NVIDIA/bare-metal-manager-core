# Tonic Client Wrapper

Provides a convenience wrapper around Tonic's generated client type, for a few moderate quality-of-life improvements.
The aim is to avoid needing to make your own wrapper type, and use this one instead.

## Example

For a gRPC method `version`:

```protobuf
rpc Version(VersionRequest) returns (BuildInfo);
message VersionRequest {
  bool display_config = 1;
}
message BuildInfo {
  // ...
}
```

The `CodeGenerator::write_rpc_client_wrapper` method will provide wrapper functions like:

```rust
pub async fn version<T: Into<crate::protos::forge::VersionRequest>>(
    &self,
    request: T,
) -> Result<crate::protos::forge::BuildInfo, tonic::Status> {
    Ok(
        self
            .connection()
            .await?
            .version(tonic::Request::new(request.into()))
            .await?
            .into_inner(),
    )
}
```

And the `CodeGenerator::write_rpc_convenience_converters` method will provide convenience converters for given RPC types
like:

```rust
impl<T: Into<bool>> From<T> for crate::protos::forge::VersionRequest {
    fn from(t: T) -> Self {
        Self { display_config: t.into() }
    }
}
```

Allowing the `Version` rpc call to be reduced from:

```rust
wrapper.version(tonic::Request::new(VersionRequest { display_config: true } )).await?.into_inner()
```

to:

```rust
wrapper.version(true).await?
```

## Features

### Eliding tonic::Request and tonic::Response

Wrapper methods accept the request types directly, rather than `tonic::Request<T>`. They also return the response types
directly, rather than `tonic::Response<T>`. This is because in practice, callers almost never care about the tonic
request/response types.

### Automatic connecting and cert reloading

Every RPC wrapper ensures a connection is made to the gRPC service, connecting on-demand on first use. Or you can use
`your_wrapper.connection().await` to connect eagerly.

Cert reloading is accomplished by letting callers implement a `ConnectionProvider` trait, which contains a method
`connection_is_stale`:

```rust
async fn connection_is_stale(&self, last_connected: SystemTime) -> bool
```

Implementations can return `true` here if, for instance, the client certificate has a newer `mtime` than the
`last_connected` time.

### Convenience conversions

For every request type (that is, the request argument of every gRPC method), if the type has exactly one field, a
`From<T: Into<FieldType>>` implementation is generated that allows any type that's convertible into that field, to be
passed. So for a request like:

```protobuf
rpc SomeMethod(SomeRequest) returns (SomeResponse);
message SomeRequest {
  required SomeId id = 1;
}
message SomeId {
  required string id = 1;
}
```

This combines nicely with each of the gRPC wrappers accepting `T: Into<RequestType>`, so that instead of having to type
out:

```rust
my_wrapper.some_method(tonic::Request::new(SomeRequest { id: SomeId { id: some_string }})).await.into_inner()
```

It becomes just:

```rust
my_wrapper.some_method(some_string).await
```

## How to use

In `build.rs`:

```rust
use tonic_client_wrapper::codegen;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = codegen::Config {
        // The name of the generated type
        wrapper_name: "MyApiClient".to_string(),
        // The client type you're already generating via tonic
        inner_rpc_client_type: "crate::my_client::MyClientT".to_string(),
        // Your protobuf files
        proto_files: vec!["proto/my_service.proto".to_string()],
        // Your include paths
        include_paths: vec!["proto".to_string()],
        // Where the generated types live within your crate (not including 
        // `crate::`, or the service name)
        generated_types_path_within_crate: "protos".to_string(),
    };

    let code_generator = codegen::CodeGenerator::new(config)?;

    // Emit the wrapper itself
    client_wrapper_generator.write_rpc_client_wrapper("src/protos/my_api_client.rs")?;
    // Emit convenience converters
    client_wrapper_generator
        .write_rpc_convenience_converters("src/protos/convenience_converters.rs")?;
    Ok(())
}
```

To use the client itself, you'll need to make an implementation of `ConnectionProvider` to yield an instance of
`my_client::MyClientT`, like:

```rust
struct MyConnectionProvider {
    url: String,
    client_config: MyClientConfig,
}

#[async_trait::async_trait]
impl tonic_client_wrapper::ConnectionProvider<MyClientT> for MyConnectionProvider {
    async fn provide_connection(&self) -> Result<MyClientT, Status> {
        // However you normally connect
        actually_connect(&self.url, &self.client_config).await
    }

    async fn connection_is_stale(&self, last_connected: SystemTime) -> bool {
        // Check if the client cert is newer than the last time we connected
        self.client_config.client_cert.as_ref().is_some_and(|client_cert| {
            if let Ok(mtime) = fs::metadata(&client_cert.cert_path).and_then(|m| m.modified()) {
                mtime > last_connected
            } else if let Ok(mtime) = fs::metadata(&client_cert.key_path).and_then(|m| m.modified())
            {
                mtime > last_connected
            } else {
                false
            }
        })
    }

    fn connection_url(&self) -> &str {
        self.url.as_str()
    }
}
```

Then you can create a client wrapper with:

```rust
MyApiClient::build(MyConnectionProvider::new(url, client_config))
```
