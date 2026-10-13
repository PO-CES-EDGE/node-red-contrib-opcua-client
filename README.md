# node-red-contrib-opcua-client

A simple Node-RED module for interacting with OPC UA (Open Platform Communications Unified Architecture) servers. Easily read, write, browse, and subscribe to data and events.

![Example image](images/example.png)

## Features
* User-friendly interface
* Automatic reconnection on network or server failures
* Single node supporting multiple functionalities
* Reuse the same OPC UA connection across multiple nodes
* Support multiple OPC UA servers

## Getting started
Navigate to your Node-RED configuration folder and run:
```bash
npm install https://github.com/PO-CES-EDGE/node-red-contrib-opcua-client
```

## Connection recovery
The connection is retried forever, every 1 to 5 seconds. If node-opcua gives up or stops retrying for 30 seconds, or the connection looks dead (sessions cannot be created, several requests time out in a row), the OPC UA client is recreated from scratch, like a flow restart, at most every 10 to 60 seconds. Sessions and subscriptions are then recreated automatically.

A session that is closed by the server or fails its keep-alive is recreated without reconnecting.

To force a reconnection from a flow, send any client node a message with `msg.reconnect = true`.

## Contributing
Feel free to open issues or pull requests for bugs and enhancements. Please note that our support focuses on critical issues.

## Acknowledgments
This module was developed using [node-opcua](https://github.com/node-opcua/node-opcua), which provides the core functionality for handling OPC UA communication.

## License
This project is licensed under the terms of the Apache 2.0 license. For more information, see the [LICENSE](LICENSE) file.
