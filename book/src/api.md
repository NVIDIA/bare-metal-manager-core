# API

The API is a gRPC transport with Protobufs that describe messages between the client and the API server.

All interaction with objects will happen throuh the API and there's an event stream that makes it possible to subscribe to events for purposes of updating internal state, watching interesting things, and debugging actions.
