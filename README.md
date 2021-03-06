# microcoap

## example

## tests

Build all tests by simply running `make` within subdirectory `/tests`.
This will create the following test applications, + use Firefox+Copper.

### piggyback

This tests is a CoAP server application which provides distinct resources:

- `/.well-known/core`: as per standard you receive resources in link-format
- `/piggyback`: the response is combined with the ACK
- `/separate`: if request is `CON` it sends separate acknowledgement and response messages, if request is `NONCON` you get a response message only (no ACK)

### request_get

This test application sends a GET request to a chosen server, it retrieves and prints `/.well-known/core`.

```
./request_get host|ip
```

### request_put

This test application sends a PUT request to a chosen server for any path with any content.

```
./request_put host|ip "path" "content"
```
