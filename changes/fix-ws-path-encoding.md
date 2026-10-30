Fixed

- WebSocket and gRPC nodes whose path or service name contains a space now connect instead of failing with "invalid uri character"; non-ASCII text is now normalized to percent-encoded UTF-8 ([#378](https://github.com/daeuniverse/honk/issues/378)).
