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
    // NOTE: retry the initial connection forever, as node-opcua already does after a connection loss
    maxRetry: -1,
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

// Let node-opcua handle normal retries. Recreate a disconnected client only
// when its connection/reconnection attempts have stopped making progress.
const RECOVERY_CHECK_INTERVAL = 5000;
const RECOVERY_NO_PROGRESS = 60000;
const CLOSE_TIMEOUT = 5000; // bound cleanup when a server does not acknowledge close

// Temporary server capacity failures can be retried without replacing the shared client.
const TEMPORARY_CAPACITY_ERROR = /BadTooManySessions|BadTooManySubscriptions|BadTooManyMonitoredItems|BadResourceUnavailable|BadServerTooBusy|BadOutOfMemory|BadTcpNotEnoughResources/;

// Errors meaning the session is unusable, even though the endpoint may still look connected
const SESSION_LOST_ERROR = /BadSession|BadSecureChannel|BadConnectionClosed|BadNotConnected|BadServerNotConnected|session.*(closed|invalid)|not connected/i;

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

function withTimeout(promise, ms, operation) {
    let timer;
    const timeout = new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(`${operation} timed out after ${ms} ms`)), ms);
    });
    return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

const DISCONNECTED = 0;
const CONNECTING = 1;
const CONNECTED = 2;
const ERROR = 3;

async function initializeClient(node, client, endpointUrl) {
    try {
        await client.connect(endpointUrl);
        // NOTE: the client may have been replaced or closed while connecting
        if (client !== node.client) return;
        node.state = CONNECTED;
        node.log(`Connected to OPC UA server at ${endpointUrl}`);
    } catch (error) {
        if (client !== node.client) return;
        node.state = ERROR;
        node.lastProgress = Date.now();
        // NOTE: no need to throw any error. The error is already propagated using the 'connection_failed' event.
        // The watchdog will recreate the client and try again.
    }
}

async function disconnectClient(node, client) {
    if (!client) return;
    try {
        client.removeAllListeners()
        await withTimeout(client.disconnect(), CLOSE_TIMEOUT, "Disconnect");
        node.log(`Disconnected from OPC UA server at ${node.endpoint}`);
    } catch (error) {
        node.warn(`Failed to disconnect cleanly from OPC UA server at ${node.endpoint}: ${error.message}`);
    }
}

async function initializeSession(node) {
    // If the server does not handle concurrency very well, we do not want to send the createSession concurrently
    // TODO: find a better way to solve this.
    await delay(Math.random() * 1000);
    if (node.closing) return;
    const client = node.endpoint.client;
    if (!client || node.endpoint.state !== CONNECTED) {
        throw new Error("client is not connected to the OPC UA server");
    }
    const session = await client.createSession(node.endpoint.userIdentity);
    // Close may finish while CreateSession is still in flight.
    if (node.closing || client !== node.endpoint.client || node.endpoint.state !== CONNECTED) {
        try {
            await withTimeout(session.close(), CLOSE_TIMEOUT, "Late session close");
        } catch (error) {
            node.debug("Error closing obsolete session (ignored): " + error);
        }
        return;
    }
    node.debug("Session created");

    // NOTE: events from a session that has already been replaced are ignored
    session.on("keepalive", () => {
        if (session !== node.session) return;
        node.debug(`keepalive ${node.name}`);
    });
    session.on("keepalive_failure", () => {
        node.debug(`keepalive_failure ${node.name}: ${node.endpoint.state}`);
        node.recoverSession(session, "keep-alive failed");
    });
    session.on("session_closed", () => {
        node.debug(`session_closed ${node.name}`);
        node.recoverSession(session, "session closed by the server");
    });

    node.session = session;
}

async function closeSession(node) {
    // NOTE: forget the session first, so that a slow close cannot erase a session created in the meantime
    const session = node.session;
    node.session = null;
    if (!session) return;
    try {
        await withTimeout(session.close(), CLOSE_TIMEOUT, "Session close");
        node.debug("Session closed");
    } catch (error) {
        node.debug("Error during session close (ignored): " + error);
    }
}

async function initializeSubscription(node) {
    const session = node.session;
    const revision = node.monitoringRevision;
    const subscription = await session.createSubscription2(node.subscriptionOptions);
    if (node.closing || session !== node.session || revision !== node.monitoringRevision) {
        try {
            await withTimeout(subscription.terminate(), CLOSE_TIMEOUT, "Late subscription close");
        } catch (error) {
            node.debug("Error closing obsolete subscription (ignored): " + error);
        }
        return;
    }
    node.debug("Subscription created");

    node.subscription = subscription;
}

async function closeSubscription(node) {
    const subscription = node.subscription;
    node.subscription = null;
    if (!subscription) return;
    try {
        await withTimeout(subscription.terminate(), CLOSE_TIMEOUT, "Subscription close");
        node.debug("Subscription closed");
    } catch (error) {
        node.debug("Error during subscription close (ignored): " + error);
    }
}

// Rebuild the session when an operation fails because the session is gone
function checkSessionError(node, error) {
    if (SESSION_LOST_ERROR.test(`${error && error.message || error}`)) {
        node.recoverSession(node.session, `operation failed: ${error.message || error}`);
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
        this.client = null;
        this.closing = false;
        this.recycling = false;
        this.lastProgress = Date.now();

        const onConnect = () => {
            this.state = CONNECTED;
            this.lastProgress = Date.now();
            this.emit("CONNECTED");
            this.debug("connected");
        }
        const onConnectFail = (error) => {
            this.state = ERROR;
            this.lastProgress = Date.now();
            this.emit("ERROR", error);
            this.debug("connection_failed");
        }
        const onBackoff = (count, _) => {
            this.state = CONNECTING;
            this.lastProgress = Date.now();
            this.emit("CONNECTING", count);
            this.debug("backoff", count);
        }
        const onStartReconnecting = () => {
            this.state = CONNECTING;
            this.lastProgress = Date.now();
            this.emit("CONNECTING");
            this.debug("start_reconnection");
        }
        const onConnectionLost = () => {
            // NOTE: node-opcua is now reconnecting, the sessions cannot be used until "connection_reestablished"
            this.state = CONNECTING;
            this.lastProgress = Date.now();
            this.emit("ERROR", new Error(`Connection lost!`));
            this.debug("connection_lost");
        }
        const onConnectionReestablished = () => {
            this.state = CONNECTED;
            this.lastProgress = Date.now();
            this.emit("CONNECTED");
            this.debug("connection_reestablished");
        }
        const onTimeoutRequest = (request) => {
            const requestName = request && request.constructor ? request.constructor.name : `${request}`;
            this.warn(`${requestName} timed out`);
            this.debug("timed_out_request");
        }

        const createClient = () => {
            const client = opcua.OPCUAClient.create(options);
            // NOTE: events from a client that has already been replaced must not change the state
            const on = (event, handler) => client.on(event, (...args) => {
                if (client === this.client) handler(...args);
            });

            on("connected", onConnect); // CONNECTED
            // NOTE: "connection_failed" occurs after {'maxRetry'} 'backoff'
            on("connection_failed", onConnectFail); // ERROR
            on("backoff", onBackoff); // CONNECTING
            on("start_reconnection", onStartReconnecting); // CONNECTING

            on("reconnection_attempt_has_failed", () => {
                this.lastProgress = Date.now();
                this.debug("reconnection_attempt_has_failed");
            });
            on("abort", () => this.debug("abort"));
            on("close", () => this.debug("close"));

            on("connection_lost", onConnectionLost);
            on("connection_reestablished", onConnectionReestablished); // CONNECTED

            on("timed_out_request", onTimeoutRequest);
            return client;
        }

        // Same as a flow restart: throw the client away and connect with a new one
        const recycleClient = async (reason) => {
            this.recycling = true;
            this.warn(`Recreating OPC UA client for ${this.endpoint}: ${reason}`);

            const oldClient = this.client;
            this.client = null;
            this.state = CONNECTING;
            // Sessions belong to the old client, the client nodes must drop them
            this.emit("RESET");
            this.emit("CONNECTING");
            try {
                await disconnectClient(this, oldClient);
            } finally {
                this.recycling = false;
            }
            if (this.closing) return;

            this.lastProgress = Date.now();
            this.client = createClient();
            await initializeClient(this, this.client, this.endpoint);
        }

        // Manual recovery is explicit; individual request/session failures
        // must not recycle the connection shared by otherwise healthy nodes.
        this.recover = (reason) => {
            if (this.closing || this.recycling) return;
            recycleClient(reason).catch((error) => this.error(`Client recovery failed: ${error}`));
        };

        const watchdog = () => {
            if (this.closing || this.recycling || this.state === CONNECTED) return;
            const stalledFor = Date.now() - this.lastProgress;
            if (stalledFor >= RECOVERY_NO_PROGRESS) {
                this.recover(`no connection progress for ${Math.round(stalledFor / 1000)}s`);
            }
        };

        this.state = CONNECTING
        this.emit("CONNECTING");

        this.client = createClient();
        (async () => { await initializeClient(this, this.client, this.endpoint) })();

        this.watchdogTimer = setInterval(watchdog, RECOVERY_CHECK_INTERVAL);

        this.on("close", async (done) => {
            this.closing = true;
            clearInterval(this.watchdogTimer);
            this.removeAllListeners();
            const client = this.client;
            this.client = null;
            // NOTE: disconnecting the client should also remove all the client listeners
            await disconnectClient(this, client);
            this.state = DISCONNECTED;
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
        node.monitoringRevision = 0;

        // BROWSE
        node.depth = config.depth || 1;
        // TODO: this could be a user input
        node.maxConcurrentRequests = 100;

        node.session = null;
        node.subscription = null;
        node.closing = false;

        // NOTE: session and subscription changes run one at a time, otherwise a reconnection
        // can interleave with an error cleanup and leave the node without a valid session
        node.lifecycle = Promise.resolve();
        const serialize = (task) => {
            node.lifecycle = node.lifecycle.then(task).catch((error) => node.error(`${error}`, {}));
            return node.lifecycle;
        };

        node.retryTimer = null;
        node.retryDelay = 1000;
        node.cancelRetry = () => {
            clearTimeout(node.retryTimer);
            node.retryTimer = null;
            node.retryDelay = 1000;
        };
        node.scheduleRetry = (error) => {
            if (!TEMPORARY_CAPACITY_ERROR.test(`${error.message || error}`)) return;
            if (node.closing || node.retryTimer || node.endpoint.state !== CONNECTED) return;
            const revision = node.monitoringRevision;
            node.retryTimer = setTimeout(() => {
                node.retryTimer = null;
                serialize(async () => {
                    if (node.closing || revision !== node.monitoringRevision || node.endpoint.state !== CONNECTED) return;
                    if (!node.session) await setupSession();
                    else await node.restoreMonitoring();
                });
            }, node.retryDelay);
            node.retryDelay = Math.min(node.retryDelay * 2, 10000);
        };

        // NOTE: clean previous sessions and subscription if needed and create new one
        // If this is called after a reconnection, we cannot guarantee that sessions and subscriptions are still valid.
        // Just in case, we recreate everything
        const setupSession = async () => {
            if (node.closing) return;
            if (node.subscription) await closeSubscription(node);
            if (node.session) await closeSession(node);
            if (node.endpoint.state !== CONNECTED) return;

            try {
                await initializeSession(node);
                if (node.closing || !node.session) return;
                node.cancelRetry();

                if (node.mode === "subscribe" || node.mode === "alarm") {
                    await node.restoreMonitoring();
                } else {
                    node.status({fill:"green",shape:"dot",text:"connected"});
                }
            }
            catch (error) {
                if (node.closing) return;
                node.scheduleRetry(error);
                node.error(`Error initializing OPC UA session: ${error}`);
                node.status({ fill: "red", shape: "dot", text: "error" });
            }
        };

        node.restoreMonitoring = async () => {
            if (node.closing || !node.session || node.endpoint.state !== CONNECTED) return;
            const revision = node.monitoringRevision;
            if (isObjectEmpty(node.monitoredItems)) {
                node.cancelRetry();
                node.status({fill:"green",shape:"dot",text:"connected"});
                return;
            }
            try {
                if (!node.subscription) await initializeSubscription(node);
                if (node.closing || !node.subscription || revision !== node.monitoringRevision) return;
                if (node.mode === "subscribe") {
                    await subscribeItems(node, node.monitoredItems);
                } else {
                    await subscribeEvents(node, node.monitoredItems);
                }
                if (!node.closing && revision === node.monitoringRevision) node.cancelRetry();
            } catch (error) {
                if (node.closing || revision !== node.monitoringRevision) return;
                node.error(`Error initializing subscription: ${error}`, {});
                node.status({ fill: "red", shape: "dot", text: "error" });
                checkSessionError(node, error);
                node.scheduleRetry(error);
            }
        };

        // Recreate the session if 'session' is still the current one
        node.recoverSession = (session, reason) => {
            if (node.closing || !session || session !== node.session) return;
            if (node.endpoint.state !== CONNECTED) return; // the endpoint will emit CONNECTED when it is back
            node.warn(`Recreating OPC UA session: ${reason}`);
            serialize(async () => {
                if (session === node.session) await setupSession();
            });
        };

        const onConnecting = (count) => {
            node.cancelRetry();
            if (node.closing) return;
            if (count) {
                node.status({ fill: "yellow", shape: "dot", text: `connecting: attempt #${count}`});
            } else {
                node.status({ fill: "yellow", shape: "dot", text: `connecting`});
            }
        };
        const onConnected = () => serialize(setupSession);
        const onError = (err) => {
            node.cancelRetry();
            return serialize(async () => {
                if (node.closing) return;
                if (node.subscription) await closeSubscription(node);
                if (node.session) await closeSession(node);
                node.error(`ERROR: ${err.message}`, {});
                node.status({ fill: "red", shape: "dot", text: "error" });
            });
        };
        // The client is being recreated: its sessions are closed with it
        const onReset = () => {
            node.cancelRetry();
            return serialize(async () => {
                node.subscription = null;
                node.session = null;
            });
        };

        node.endpoint.on("CONNECTING", onConnecting);
        node.endpoint.on("CONNECTED", onConnected);
        node.endpoint.on("ERROR", onError);
        node.endpoint.on("RESET", onReset);

        // NOTE: This code is required if a new client node is instantiated using an already connected endpoint.
        const state = node.endpoint.state;
        if (state === CONNECTED) {
            serialize(setupSession);
        } else if (state === CONNECTING) {
            node.status({ fill: "yellow", shape: "dot", text: "connecting"});
        } else if (state === ERROR) {
            node.status({ fill: "red", shape: "dot", text: "error"});
        } else {
            node.status({ fill: "red", shape: "dot", text: "disconnected"});
        }

        node.on("input", async (msg) => {
            if (node.closing) return;
            // Manual recovery from a flow: recreate the OPC UA client, like a flow restart
            if (msg.reconnect) {
                node.endpoint.recover("requested by msg.reconnect");
                return;
            }
            if ((node.mode === "subscribe" || node.mode === "alarm") && msg.hasOwnProperty("reset")) {
                node.monitoringRevision++;
                node.cancelRetry();
                node.monitoredItems = {};
                await serialize(() => handleSubscriptionAndEvents(node, msg));
                return;
            }
            if (!node.session || node.endpoint.state !== CONNECTED) {
                node.error("Impossible to execute operation, client is not connected to the OPC UA server.", msg)
                // The endpoint is connected but this node lost its session: try to get a new one
                if (node.endpoint.state === CONNECTED) {
                    serialize(async () => {
                        if (!node.session) await setupSession();
                    });
                }
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
                    await serialize(() => handleSubscriptionAndEvents(node, msg))
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
            node.closing = true;
            node.cancelRetry();
            node.monitoringRevision++;
            // NOTE: the endpoint may outlive this node (partial deploy), so the listeners must be removed
            node.endpoint.removeListener("CONNECTING", onConnecting);
            node.endpoint.removeListener("CONNECTED", onConnected);
            node.endpoint.removeListener("ERROR", onError);
            node.endpoint.removeListener("RESET", onReset);
            node.recoverSession = () => {};
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
        checkSessionError(node, err);
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

function buildWriteValue(dataType, value) {
    const validator = isTypeValid[dataType];
    if (!validator) {
        throw new Error(`Unsupported dataType '${dataType}'. Supported types are: ${Object.keys(isTypeValid).map(key => `'${key}'`).join(", ")}`);
    }

    // node-opcua represents scalar Int64 and UInt64 values as [high, low].
    // Prefer the scalar interpretation when the complete value validates as one.
    const is64BitScalar = (dataType === "Int64" || dataType === "UInt64") &&
        Array.isArray(value) &&
        !value.some(Array.isArray) &&
        validator(value);
    const isArray = Array.isArray(value) && !is64BitScalar;

    if (isArray) {
        for (const [index, item] of value.entries()) {
            if (!validator(item)) {
                throw new Error(`'${item}' at index ${index} is not a valid value for type '${dataType}'`);
            }
        }
    } else if (!validator(value)) {
        throw new Error(`'${value}' is not a valid value for type '${dataType}'`);
    }

    return {
        dataType: opcua.DataType[dataType],
        arrayType: isArray ? opcua.VariantArrayType.Array : opcua.VariantArrayType.Scalar,
        value: value
    }
}

async function handleWrite(node, msg) {
    
    if (!msg.payload || typeof msg.payload !== 'object' || Array.isArray(msg.payload)) {
        node.error(`Invalid input ${JSON.stringify(msg.payload)}: payload should be an object with variable names as keys and OPC UA tags as values.`, msg);
        return;
    }

    if (Object.keys(msg.payload).length === 0) {
        node.error("Invalid input: payload must contain at least one item to write.", msg);
        return;
    }

    const nodesToWrite = [];
    const keys = [];
    const errorDetails = [];

    for (const [key, value] of Object.entries(msg.payload)) {
        if (!value ||
            typeof value !== 'object' ||
            Array.isArray(value) ||
            !value.nodeId || 
            value.value === undefined || 
            value.dataType === undefined
        ) {
            errorDetails.push({
                variableName: key,
                nodeId: value && typeof value === 'object' ? value.nodeId : undefined,
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

    if (nodesToWrite.length === 0) {
        node.error(`Failed to write the following item/s:\n${errorDetails.map((variable) => `- ${variable.variableName} [${variable.nodeId}]: ${variable.errorDescription}`).join('\n')}`, {errorDetails});
        return;
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
        checkSessionError(node, error);
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
            checkSessionError(node, error);

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
    if (node.closing) return;
    if (msg.hasOwnProperty("reset")) {
        // Clear intent even if initialization never produced a subscription.
        node.monitoredItems = {};
        await closeSubscription(node);
        if (!node.closing && node.session) node.status({fill:"green",shape:"dot",text:"connected"});
        return;
    }
    const revision = node.monitoringRevision;

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
    const session = node.session;

    // Prepare read requests to check if event types exist
    const itemsToRead = Object.values(node.monitoredItems).map((nodeId) => ({
        nodeId: nodeId,
        attributeId: opcua.AttributeIds.NodeClass,
    }));

    let dataValues = null;
    try {
        dataValues = await node.session.read(itemsToRead);
    } catch (err) {
        if (node.closing || revision !== node.monitoringRevision) return;
        node.error(`Error preprocessing event types: ${err}`, msg);
        checkSessionError(node, err);
        return;
    }

    if (node.closing || session !== node.session || revision !== node.monitoringRevision) return;

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

    if (node.mode === "alarm" && Object.keys(node.monitoredItems).length > 4) {
        node.warn(`Subscribing to more than 4 events is not recommanded! Alternatively, you can split the load across multiple nodes.`)
    }
    await node.restoreMonitoring();
    // NOTE: Maybe we should return a msg.
}

async function subscribeItems(node, monitoredItems) {
    monitoredItems = { ...monitoredItems };
    const subscription = node.subscription;
    const revision = node.monitoringRevision;
    const current = () => !node.closing && subscription === node.subscription && revision === node.monitoringRevision;
    const processedItems = preprocessItems(monitoredItems);
    try {
        const itemGroup = opcua.ClientMonitoredItemGroup.create(
            node.subscription,
            Object.values(processedItems),
            node.monitoredItemsOptions,
            opcua.TimestampsToReturn.Both
        )

        itemGroup.on("initialized", () => {
            if (!current()) return;
            node.status({ fill: "green", shape: "dot", text: `${Object.keys(monitoredItems).length} items subscribed`});
        })
        itemGroup.on("err", (message) => { if (current()) node.error(`Item group error: ${message}`, {}); });
        itemGroup.on("changed", (_, dataValue, index) => {
            if (!current()) return;
            
            const key = Object.keys(monitoredItems)[index];
            // NOTE: need to create a new message to avoid msgid conflict
            // if I do not do that, 'key' is not attached correctly
            const msg = {
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
    monitoredItems = { ...monitoredItems };
    const subscription = node.subscription;
    const revision = node.monitoringRevision;
    const current = () => !node.closing && subscription === node.subscription && revision === node.monitoringRevision;

    try {
        for (const [key, value] of Object.entries(monitoredItems)) {
            const eventTypeId = opcua.resolveNodeId(value);
            const fields = await opcua.extractConditionFields(node.session, eventTypeId);
            if (!current()) return;
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
                if (!current()) return;
                // NOTE: I'm not sure this is needed
                await opcua.callConditionRefresh(node.session, node.subscription.subscriptionId);
            })
            itemGroup.on("err", (message) => { if (current()) node.error(`Event group error: ${message}`, {}); });
            itemGroup.on("changed", (dataValue) => {
                if (!current()) return;
                const msg = {
                    "payload": {
                        [key]: opcua.fieldsToJson(fields, dataValue, false)
                    }
                }
                // NOTE: should we return information about the session?
                node.send(msg);
            });
        }
        if (current()) node.status({ fill: "green", shape: "dot", text: `${Object.keys(node.monitoredItems).length} events subscribed`});
    } catch (error) {
        node.error(error, {});
        node.status({ fill: "red", shape: "dot", text: "error"});
    }
}
