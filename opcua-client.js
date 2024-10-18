const { EventEmitter } = require('events');
const opcua = require('node-opcua');

const securityModes = {
    "None": opcua.MessageSecurityMode.None,
    "Sign": opcua.MessageSecurityMode.Sign,
    "SignAndEncrypt": opcua.MessageSecurityMode.SignAndEncrypt
};

const securityPolicies = {
    "None": opcua.SecurityPolicy.None,
    "Basic128": opcua.SecurityPolicy.Basic128,
    "Basic128Rsa15": opcua.SecurityPolicy.Basic128Rsa15,
    "Basic192": opcua.SecurityPolicy.Basic192,
    "Basic192Rsa15": opcua.SecurityPolicy.Basic192Rsa15,
    "Basic256": opcua.SecurityPolicy.Basic256,
    "Basic256Rsa15": opcua.SecurityPolicy.Basic256Rsa15,
    "Basic256Sha256": opcua.SecurityPolicy.Basic256Sha256,
    "Aes128_Sha256_RsaOaep": opcua.SecurityPolicy.Aes128_Sha256_RsaOaep,
    "PubSub_Aes128_CTR": opcua.SecurityPolicy.PubSub_Aes128_CTR,
    "PubSub_Aes256_CTR": opcua.SecurityPolicy.PubSub_Aes256_CTR,
}

const connectionStrategy = {
    maxRetry: 1,
    initialDelay: 1000,
    maxDelay: 5000
};

const options = {
    securityMode: securityModes["None"],
    securityPolicy: securityPolicies["None"],
    defaultSecureTokenLifetime: 40000 * 5,
    endpointMustExist: false, // Potentially useless
    connectionStrategy: connectionStrategy,
    keepSessionAlive: true,
    keepAliveInterval: 5000,
    requestedSessionTimeout: 120000, // 2 minutes
    // NOTE: THIS PARAMETER IS NEEDED FOR PROPER AUTOMATIC RECONNECTION
    transportTimeout: 10000,
    automaticallyAcceptUnknownCertificate: true
}

const subscriptionOptions = {
    maxNotificationsPerPublish: 1000,
    publishingEnabled: true,
    requestedLifetimeCount: 100,
    requestedMaxKeepAliveCount: 10,
    requestedPublishingInterval: 1000
};

const monitoredItemsOptions = 
{
    samplingInterval: 100,
    discardOldest: true,
    queueSize: 10,
};

const isObjectEmpty = (object) => {
    return Object.keys(object).length === 0;
}

function delay(ms) {
    return new Promise(resolve => {
        setTimeout(resolve, ms);
    });
}

const DISCONNECTED = 0;
const CONNECTING = 1;
const CONNECTED = 2;
const ERROR = 3;

async function initializeClient(node, client, endpointUrl) {
    try {
        await client.connect(endpointUrl);
        node.state = CONNECTED;
        node.log(`Connected to OPC UA server at ${endpointUrl}`);
    } catch (error) {
        node.state = ERROR;
        // NOTE: no need to throw any error. The error is already propagated using the 'connection_failed' event.
    }
}

async function disconnectClient(node, client) {
    try {
        client.removeAllListeners()
        await client.disconnect();
        node.state = DISCONNECTED;
        node.log(`Disconnected from OPC UA server at ${node.endpoint}`);
        node.client = null;
    } catch (error) {
        node.state = ERROR;
        throw new Error(`Failed to disconnect to OPC UA server: ${error}`);
    }
}

async function initializeSession(node, client) {
    // If the server does not handle concurrency very well, we do not want to send the createSession concurrently 
    // TODO: find a better way to solve this.
    await delay(Math.random() * 1000);
    const session = await client.createSession(node.endpoint.userIdentity);
    node.debug("Session created");

    node.session = session;
}

async function closeSession(node) {
    try {
        await node.session.close();
        node.session = null;
        node.debug("Session closed");
    } catch (error) {
        node.error("Error during session close: " + error);
    }
}

async function initializeSubscription(node) {
    const subscription = await node.session.createSubscription2(node.subscriptionOptions);
    node.debug("Subscription created");

    node.subscription = subscription;
}

async function closeSubscription(node) {
    try {
        await node.subscription.terminate();
        node.subscription = null;
        node.debug("Subscription closed");
    } catch (error) {
        node.error("Error during subscription close: ", + error);
    }
}

function preprocessItems(items) {
    const nodesToRead = {};
    for (const [key, value] of Object.entries(items)) {
        nodesToRead[key] = {
            nodeId: value,
            attributeId: opcua.AttributeIds.Value,
            TimestampsToReturn: opcua.TimestampsToReturn.Both
        }
    }
    return nodesToRead;
}

module.exports = function(RED) {
    function OPCUAClientEndpoint(config) {
        EventEmitter.call(this); 
        // Avoid warnings
        this.setMaxListeners(0);

        RED.nodes.createNode(this, config);
        
        // USER INPUTS
        this.endpoint = config.endpoint;
        this.securityMode = config.securityMode;
        this.securityPolicy = config.securityPolicy;
        this.userIdentity = { type: opcua.UserTokenType.Anonymous };
        if (config.userIdentity === "UserName") {
            this.userIdentity = {
                type: opcua.UserTokenType.UserName,
                userName: this.credentials.user,
                password: this.credentials.password
            };
        }

        this.state = DISCONNECTED;

        this.client = opcua.OPCUAClient.create(options);

        const onConnect = () => {
            this.state = CONNECTED;
            this.emit("CONNECTED");
            this.debug("connected");
        }
        const onConnectFail = (error) => {
            this.state = ERROR;
            this.emit("ERROR", error);
            this.debug("connection_failed");
        }
        const onBackoff = (count, _) => {
            this.state = CONNECTING;
            this.emit("CONNECTING", count);
            this.debug("backoff", count);
        }
        const onStartReconnecting = () => {
            this.state = CONNECTING;
            this.emit("CONNECTING");
            this.debug("start_reconnection");
        }
        const onConnectionLost = () => { 
            this.emit("ERROR", new Error(`Connection lost!`));
            this.debug("connection_lost");
        }
        const onConnectionReestablished = () => { 
            this.state = CONNECTED;
            this.emit("CONNECTED");
            this.debug("connection_reestablished");
        }
        const onTimeoutRequest = (request) => {
            this.state = ERROR;
            this.emit("ERROR", new Error(`${request} timed out!`));
            this.debug("timed_out_request");
        }

        this.state = CONNECTING
        this.emit("CONNECTING");

        this.client.on("connected", onConnect); // CONNECTED
        // NOTE: "connection_failed" occurs after {'maxRetry'} 'backoff' 
        this.client.on("connection_failed", onConnectFail); // ERROR
        this.client.on("backoff", onBackoff); // CONNECTING
        this.client.on("start_reconnection", onStartReconnecting); // CONNECTING

        // NOTE: I was never able to get this event
        this.client.on("reconnection_attempt_has_failed", () => this.debug("reconnection_attempt_has_failed"));
        this.client.on("abort", () => this.debug("abort"));
        this.client.on("close", () => this.debug("close"));

        this.client.on("connection_lost", onConnectionLost);
        this.client.on("connection_reestablished", onConnectionReestablished); // CONNECTED
        
        this.client.on("timed_out_request", onTimeoutRequest); // ERROR

        (async () => { await initializeClient(this, this.client, this.endpoint) })();
        
        this.on("close", async (done) => {
            this.removeAllListeners();
            // NOTE: disconnecting the client should also remove all the client listeners
            await disconnectClient(this, this.client);
            if (done) done();
        })
    }
    RED.nodes.registerType("opcua client endpoint", OPCUAClientEndpoint, {
        credentials: {
            user: {type:"text"},
            password: {type: "password"}
        }
    });

    function OPCUAClient(config) {
        RED.nodes.createNode(this, config);
        var node = this;
        
        node.name = config.name;
        node.endpoint = RED.nodes.getNode(config.endpoint);
        if (!node.endpoint) {
            node.error("Missing OPCUA endpoint configuration")
            node.status({ fill: "red", shape: "dot", text: "disconnected" });
            node.on("input", async () => {node.error("Cannot execute operation: missing OPC UA endpoint configuration!")});
            return;
        }
        
        node.mode = config.mode;
        // READ
        // SUBSCRIBE & EVENTS
        node.subscriptionOptions = {
            ...subscriptionOptions,
            requestedPublishingInterval: parseInt(config.publishingInterval)
        };
        
        node.monitoredItemsOptions = 
        {
            ...monitoredItemsOptions,
            samplingInterval: parseInt(config.samplingInterval),
            queueSize: parseInt(config.queueSize),
        };
        
        node.monitoredItems = {};

        // BROWSE
        node.depth = config.depth || 1;
        // TODO: this could be a user input
        node.maxConcurrentRequests = 100;
        
        const {client, state} = node.endpoint;

        node.session = null;
        node.subscription = null;
        
        node.endpoint.on("CONNECTING", async (count) => {
            if (count) {
                node.status({ fill: "yellow", shape: "dot", text: `connecting: attempt #${count}`});
            } else {
                node.status({ fill: "yellow", shape: "dot", text: `connecting`});
            }
        })

        node.endpoint.on("CONNECTED", async () => {
            // NOTE: clean previous sessions and subscription if needed and create new one
            // If this event is triggered after a reconnection, we cannot guarantee that sessions and subscriptions are still valid.
            // Just in case, we recreate everything
            if (node.subscription) await closeSubscription(node);
            if (node.session) await closeSession(node);
                
            try {
                await initializeSession(node, client);
                
                node.session.on("keepalive", () => node.debug(`keepalive ${node.name}`))
                node.session.on("keepalive_failure", () => node.debug(`keepalive_failure ${node.name}: ${state}`));
                
                if (node.mode === "subscribe") {
                    if (!isObjectEmpty(node.monitoredItems)) {
                        await initializeSubscription(node);
                        await subscribeItems(node, node.monitoredItems);
                    } else {
                        node.status({fill:"green",shape:"dot",text:"connected"});
                    }
                } else if (node.mode === "alarm") {
                    if (!isObjectEmpty(node.monitoredItems)) {
                        await initializeSubscription(node);
                        await subscribeEvents(node, node.monitoredItems);
                    } else {
                        node.status({fill:"green",shape:"dot",text:"connected"});
                    }
                } else {
                    node.status({fill:"green",shape:"dot",text:"connected"});
                }

            }
            catch (error) {
                node.error(`Error initializing OPC UA session: ${error}`);
                node.status({ fill: "red", shape: "dot", text: "error" });
            }
        });
        
        node.endpoint.on("ERROR", async (err) => {
            if (node.subscription) await closeSubscription(node);
            if (node.session) await closeSession(node);
            node.error(`ERROR: ${err.message}`, {});
            node.status({ fill: "red", shape: "dot", text: "error" });
        })

        // NOTE: This code is required if a new client node is instantiated using an already connected endpoint.
        if (state === CONNECTED) {
            // NOTE: in this case we do not need to close any session or subscription,
            // we are sure that they were not created before
            (async () => {
                try {
                    if (!node.session) {
                        await initializeSession(node, client);
                    }
                    
                    node.session.on("keepalive", () => node.debug(`keepalive ${node.name}`))
                    node.session.on("keepalive_failure", () => node.debug(`keepalive_failure ${node.name}: ${state}`));
                    
                    node.status({fill:"green",shape:"dot",text:"connected"});
                }
                catch (error) {
                    node.error(`Error initializing OPC UA session: ${error}`, {})
                    node.status({ fill: "red", shape: "dot", text: "error" });
                }
            })();
        } else if (state === CONNECTING) {
            node.status({ fill: "yellow", shape: "dot", text: "connecting"});
        } else if (state === ERROR) {
            node.status({ fill: "red", shape: "dot", text: "error"});
        } else {
            node.status({ fill: "red", shape: "dot", text: "disconnected"});
        }

        node.on("input", async (msg) => { 
            if (!node.session) {
                node.error("Impossible to execute operation, client is not connected to the OPC UA server.", msg)
                return;
            };
            switch (node.mode) {
                case "read": {
                    await handleRead(node, msg);
                    break;
                }
                case "subscribe":
                case "alarm":
                {
                    await handleSubscriptionAndEvents(node, msg)
                    break;
                }
                case "browse": {
                    await handleBrowse(node, msg);
                    break;
                }
                case "write": {
                    await handleWrite(node, msg);
                    break;
                }
                default: {
                    node.error(`${node.mode} is not implemented!`, msg);
                }
            }
        });
        node.on("close", async (done) => {
            if (node.subscription) await closeSubscription(node);
            if (node.session) await closeSession(node);
            if (done) done();
        });
    }
    RED.nodes.registerType("opcua client", OPCUAClient);
}

async function handleRead(node, msg) {
    
    if (!msg.payload || typeof msg.payload !== 'object') {
        node.error(`Invalid input ${JSON.stringify(msg.payload)}: payload must be an object with variable names as keys and OPC UA tags as values.`, msg);
        return;
    }

    const preprocessedInput = preprocessItems(msg.payload);
    try {
        const items = Object.values(preprocessedInput);
        const data = await node.session.read(items);
        const result = {};
        const errorDetails = [];
        
        Object.keys(preprocessedInput).forEach((key, index) => {
            if (data[index].statusCode.value !== 0) {
                errorDetails.push({
                    variableName: key,
                    nodeId: msg.payload[key],
                    errorDescription: data[index].statusCode.description
                })
            }
            else {
                // Post-process data
                result[key] = {
                    ...data[index],
                    dataType: opcua.DataType[data[index].value.dataType],
                    arrayType: opcua.VariantArrayType[data[index].value.arrayType],
                    value: data[index].value.value,
                    statusCode: data[index].statusCode.value,
                }
            }
        });


        if (!isObjectEmpty(result)) {
            msg["payload"] = result;
            // NOTE: should we return information about the session?
            node.send(msg);
        }
        
        if (errorDetails.length > 0) {
            node.error(`Failed to read the following item/s:\n${errorDetails.map((variable) => `- ${variable.variableName} [${variable.nodeId}]: ${variable.errorDescription}`).join('\n')}`, {errorDetails});
        }
    }
    catch (err) {
        node.error(`${err}`, msg);
    }
}

const isTypeValid = {
    "Boolean": opcua.isValidBoolean,
    "Byte": opcua.isValidByte,
    "SByte": opcua.isValidSByte,
    "UInt8": opcua.isValidUInt8,
    "Int8": opcua.isValidInt8,
    "UInt16": opcua.isValidUInt16,
    "Int16": opcua.isValidInt16,
    "UInt32": opcua.isValidUInt32,
    "Int32": opcua.isValidInt32,
    "UInt64": opcua.isValidUInt64,
    "Int64": opcua.isValidInt64,
    "Float": opcua.isValidFloat,
    "Double": opcua.isValidDouble,
    "String": opcua.isValidString,
    "DateTime": opcua.isValidDateTime,
}

// NOTE: we only support writing 'Scalar' for now
function buildWriteValue(dataType, value) {
    if (isTypeValid[dataType]) {
        if (isTypeValid[dataType](value)) {
            return {
                dataType: opcua.DataType[dataType],
                arrayType: opcua.VariantArrayType.Scalar,
                value: value
            }
        } else {
            throw new Error(`'${value}' is not a valid value for type '${dataType}'`);
        }
    } else {
        throw new Error(`Unsupported dataType '${dataType}'. Supported types are: ${Object.keys(isTypeValid).map(key => `'${key}'`).join(", ")}`);
    }
}

async function handleWrite(node, msg) {
    
    if (!msg.payload || typeof msg.payload !== 'object') {
        node.error(`Invalid input ${JSON.stringify(msg.payload)}: payload should be an object with variable names as keys and OPC UA tags as values.`, msg);
        return;
    }

    const nodesToWrite = [];
    const keys = [];
    const errorDetails = [];

    for (const [key, value] of Object.entries(msg.payload)) {
        if (!value || 
            !value.nodeId || 
            value.value === undefined || 
            value.dataType === undefined
        ) {
            errorDetails.push({
                variableName: key,
                nodeId: value.nodeId,
                errorDescription: "Invalid payload structure. Please provide a 'nodeId', 'value', and 'dataType'."
            })
            continue;
        }
        try {
            const variant = buildWriteValue(value.dataType, value.value);
            const writeValue = {
                nodeId: value.nodeId,
                attributeId: opcua.AttributeIds.Value,
                value: { value: variant }
            };
            nodesToWrite.push(writeValue);
            keys.push(key); // Keep track of the key variable name
        } catch (error) {
            errorDetails.push({
                variableName: key,
                nodeId: value.nodeId,
                errorDescription: error.message
            })
        }
    }
    
    try {
        const statusCodes = await node.session.write(nodesToWrite);
        statusCodes.forEach((code, index) => {
            if (code.value !== 0) {
                const nodeId = nodesToWrite[index].nodeId;
                const key = keys[index];
                errorDetails.push({
                    variableName: key,
                    nodeId: nodeId,
                    errorDescription: code.description
                })
            }
        });
        
        if (errorDetails.length > 0) {
            node.error(`Failed to write the following item/s:\n${errorDetails.map((variable) => `- ${variable.variableName} [${variable.nodeId}]: ${variable.errorDescription}`).join('\n')}`, {errorDetails});
        }
        
        // NOTE: Maybe we should return a msg.
    } catch (error) {
        node.error(`Error writing to OPC UA server: ${error.message}`, msg);
    }
}

async function handleBrowse(node, msg) {
    
    if (!msg.payload || typeof msg.payload !== 'string') {
        node.error(`Invalid input: payload should be a string representing the nodeId to browse. Received: ${JSON.stringify(msg.payload)}`, msg);
        return;
    }

    node.status({ fill: "blue", shape: "dot", text: "Browsing..." });

    const nodeToBrowse = msg.payload;
    const depth = node.depth;
    const maxConcurrentRequests = node.maxConcurrentRequests;

    const rootNode = {
        nodeId: nodeToBrowse,
    }

    const read = async (nodeId, parentNode) => {
        const data = await node.session.read(
            {
                nodeId: nodeId, 
                attributeId: 
                opcua.AttributeIds.Value
            }
        );
        parentNode.value = data.value.value;
        parentNode.dataType= opcua.DataType[data.value.dataType]
    };
    
    const browse = async (nodeId, parentNode, depth) => {
        if (depth === 0) return;
        const browseResult = await node.session.browse(
            { 
                nodeId: nodeId, 
                resultMask: 63 
            }
        );
        if (browseResult.statusCode.value !== 0) {
            throw new Error(`Impossible to browse item '${nodeId}': ${browseResult.statusCode.description}`);
        }

        const childNodes = [];
        for (const reference of browseResult.references) {
            const childNode = {
                nodeId: reference.nodeId.toString(),
                browseName: reference.browseName.toString(),
                nodeClass: opcua.NodeClass[reference.nodeClass],
            }

            if (reference.isForward && depth > 1) {
                tasksQueue.push(() => browse(reference.nodeId, childNode, depth - 1))
            }

            if (reference.nodeClass === opcua.NodeClass.Variable) { // Variable
                tasksQueue.push(() => read(reference.nodeId, childNode));
            }
            childNodes.push(childNode);
        }

        if (childNodes.length > 0) {
            parentNode.children = childNodes;
        }
    }

    const tasksQueue = [async () => browse(nodeToBrowse, rootNode, depth)];
    
    while (tasksQueue.length > 0) {
        const tasksToRun = tasksQueue.splice(0, maxConcurrentRequests);
        try {
            await Promise.all(tasksToRun.map((task) => task()));
        } catch (error) {
            node.error(error.message, {});
            node.status({ fill: "red",  shape: "dot", text: "error"})

            // RESET status after 5 seconds
            setTimeout(() => {
                node.status({ fill: "green", shape: "dot", text: "connected" });
            }, 5000);
            return;
        }
    }
    msg.payload = rootNode;
    node.send(msg);
    node.status({ fill: "green", shape: "dot", text: "connected" });
}

async function handleSubscriptionAndEvents(node, msg) {
    if (msg.hasOwnProperty("reset")) {
        // NOTE: Terminating the subscription also deletes all the monitoredItems
        if (node.subscription) {
            await closeSubscription(node)
            node.monitoredItems = {};
            node.status({fill:"green",shape:"dot",text:"connected"});
        }
        return;
    }

    if (!msg.payload || typeof msg.payload !== 'object') {
        node.error(`Invalid input ${JSON.stringify(msg.payload)}: payload should be an object with variable names as keys and OPC UA tags as values.`, msg);
        return;
    }

    const errorDetails = [];
    for (const [key, value] of Object.entries(msg.payload)) {
        if (node.monitoredItems.hasOwnProperty(key)) {
            if (node.monitoredItems[key] === value) {
                errorDetails.push({
                    variableName: key,
                    nodeId: value,
                    errorDescription: `Item is already registered. Skipping duplicate subscription.`
                });
            } else {
                errorDetails.push({
                    variableName: key,
                    nodeId: value,
                    errorDescription: `Item conflicts with a previously registered item. Please use a unique key for each item.`
                });
            }
        } else {
            node.monitoredItems[key] = value;
        }
    }

    if (node.subscription) await closeSubscription(node);
    try {
        await initializeSubscription(node);
    } catch (err) {
        node.error("Error initializing subscription:", err);
        return;
    }
    
    // Prepare read requests to check if event types exist
    const itemsToRead = Object.values(node.monitoredItems).map((nodeId) => ({
        nodeId: nodeId,
        attributeId: opcua.AttributeIds.NodeClass,
    }));

    let dataValues = null;
    try {
        dataValues = await node.session.read(itemsToRead);
    } catch (err) {
        node.error("Error preprocessing event types:", err);
        return;
    }

    // Check if the nodes are of NodeClass ObjectType (event types)
    Object.keys(node.monitoredItems).forEach((key, index) => {
        const dataValue = dataValues[index];
        if (!dataValue.statusCode.isGood()) {
            errorDetails.push({
                variableName: key,
                nodeId: node.monitoredItems[key],
                errorDescription: dataValue.statusCode.description
            });
            delete node.monitoredItems[key];
        }
    });

    if (errorDetails.length > 0) {
        node.error(`Failed to subscribe the following item/s:\n${errorDetails.map((variable) => `- ${variable.variableName} [${variable.nodeId}]: ${variable.errorDescription}`).join('\n')}`, {errorDetails});
    }
    
    if (Object.keys(node.monitoredItems).length === 0) {
        node.warn("No valid item types to subscribe to after validation.");
        return;
    }

    if (node.mode === "subscribe") {
        subscribeItems(node, node.monitoredItems)
    }
    else if (node.mode === "alarm") {
        // TODO: finetune the maximum amount of items
        if (Object.keys(node.monitoredItems).length > 4) {
            node.warn(`Subscribing to more than 4 events is not recommanded! Alternatively, you can split the load across multiple nodes.`)
        }
        subscribeEvents(node, node.monitoredItems)
    }
    // NOTE: Maybe we should return a msg.
}

async function subscribeItems(node, monitoredItems) {
    const processedItems = preprocessItems(monitoredItems);
    try {
        const itemGroup = opcua.ClientMonitoredItemGroup.create(
            node.subscription,
            Object.values(processedItems),
            node.monitoredItemsOptions,
            opcua.TimestampsToReturn.Both
        )

        itemGroup.on("initialized", () => {
            node.status({ fill: "green", shape: "dot", text: `${Object.keys(monitoredItems).length} items subscribed`});
        })
        itemGroup.on("err", (message) => node.error(`Item group error: ${message}`, {}));
        itemGroup.on("changed", (_, dataValue, index) => {
            
            const key = Object.keys(monitoredItems)[index];
            // NOTE: need to create a new message to avoid msgid conflict
            // if I do not do that, 'key' is not attached correctly
            msg = {
                "payload": {
                    [key]: {
                        ...dataValue,
                        dataType: opcua.DataType[dataValue.value.dataType],
                        arrayType: opcua.VariantArrayType[dataValue.value.arrayType],
                        value: dataValue.value.value,
                        statusCode: dataValue.statusCode.value,
                    }
                }
            }
            // NOTE: should we return information about the session?
            node.send(msg);
        });
    }
    catch (error) {
        node.error(error, {});
        node.status({ fill: "red", shape: "dot", text: "error"});
    }
}

async function subscribeEvents(node, monitoredItems) {

    try {
        for (const [key, value] of Object.entries(monitoredItems)) {
            const eventTypeId = opcua.resolveNodeId(value);
            const fields = await opcua.extractConditionFields(node.session, eventTypeId);
            const eventFilter = opcua.constructEventFilter(fields, opcua.ofType(eventTypeId));

            const itemGroup = opcua.ClientMonitoredItem.create(
                node.subscription,
                {
                    // TODO: at some point this should be an input and not hardcoded
                    nodeId: opcua.resolveNodeId("Server"),
                    attributeId: opcua.AttributeIds.EventNotifier 
                },
                {...node.monitoredItemsOptions, filter: eventFilter},
                opcua.TimestampsToReturn.Both
            )

            itemGroup.on("initialized", async () => {
                // NOTE: I'm not sure this is needed
                await opcua.callConditionRefresh(node.session, node.subscription.subscriptionId);
            })
            itemGroup.on("err", (message) => node.error(`Event group error: ${message}`, {}));
            itemGroup.on("changed", (dataValue) => {
                msg = {
                    "payload": {
                        [key]: opcua.fieldsToJson(fields, dataValue, false)
                    }
                }
                // NOTE: should we return information about the session?
                node.send(msg);
            });
        }
        node.status({ fill: "green", shape: "dot", text: `${Object.keys(node.monitoredItems).length} events subscribed`});
    } catch (error) {
        node.error(error, {});
        node.status({ fill: "red", shape: "dot", text: "error"});
    }
}
