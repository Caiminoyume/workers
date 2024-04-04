import { connect } from 'cloudflare:sockets';

const password = '';
const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;
const encodePassword = new TextEncoder().encode(password);
const passwordSha224 = await crypto.subtle.digest({ name: 'SHA-224', }, encodePassword);

export default {
    /**
     * @param {import("@cloudflare/workers-types").Request} request
     * @returns {Promise<Response>}
     */
    async fetch(request) {
        try {
            const upgradeHeader = request.headers.get('Upgrade');
            if (!upgradeHeader || upgradeHeader !== 'websocket') {
                return new Response('Not found', { status: 404 });
            } else {
                return await trojanOverWSHandler(request);
            }
        } catch (err) {
			/** @type {Error} */ let e = err;
            return new Response(e.toString());
        }
    },
};

/**
 * @param {import("@cloudflare/workers-types").Request} request
 */
async function trojanOverWSHandler(request) {
    /** @type {import("@cloudflare/workers-types").WebSocket[]} */
    const webSocketPair = new WebSocketPair();
    const [client, webSocket] = Object.values(webSocketPair);

    webSocket.accept();

    let address = '';
    let portWithRandomLog = '';
    const log = (/** @type {string} */ info, /** @type {string | undefined} */ event) => {
        console.log(`[${address}:${portWithRandomLog}] ${info}`, event || '');
    };
    const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';

    const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

    /** @type {{ value: import("@cloudflare/workers-types").Socket | null}}*/
    let remoteSocketWapper = {
        value: null,
    };
    let udpStreamWrite = null;
    let isDns = false;

    // ws --> remote
    readableWebSocketStream.pipeTo(new WritableStream({
        async write(chunk, controller) {
            if (isDns && udpStreamWrite) {
                return udpStreamWrite(chunk);
            }
            if (remoteSocketWapper.value) {
                const writer = remoteSocketWapper.value.writable.getWriter()
                await writer.write(chunk);
                writer.releaseLock();
                return;
            }

            const {
                hasError,
                message,
                portRemote = 443,
                addressRemote = '',
                rawDataIndex,
                isUDP,
            } = processTrojanHeader(chunk, log);
            address = addressRemote;
            portWithRandomLog = `${portRemote}--${Math.random()} ${isUDP ? 'udp ' : 'tcp '} `;
            if (hasError) {
                // controller.error(message);
                throw new Error(message); // cf seems has bug, controller.error will not end stream
                // webSocket.close(1000, message);
                return;
            }
            // if UDP but port not DNS port, close it
            if (isUDP) {
                if (portRemote === 53) {
                    isDns = true;
                } else {
                    // controller.error('UDP proxy only enable for DNS which is port 53');
                    throw new Error('UDP proxy only enable for DNS which is port 53'); // cf seems has bug, controller.error will not end stream
                    return;
                }
            }
            const rawClientData = chunk.slice(rawDataIndex);

            // TODO: support udp here when cf runtime has udp support
            if (isDns) {
                const { write } = await handleUDPOutBound(webSocket, log);
                udpStreamWrite = write;
                udpStreamWrite(rawClientData);
                return;
            }
            handleTCPOutBound(remoteSocketWapper, addressRemote, portRemote, rawClientData, webSocket, log);
        },
        close() {
            log(`readableWebSocketStream is close`);
        },
        abort(reason) {
            log(`readableWebSocketStream is abort`, JSON.stringify(reason));
        },
    })).catch((err) => {
        log('readableWebSocketStream pipeTo error', err);
    });

    return new Response(null, {
        status: 101,
        webSocket: client,
    });
}

/**
 * @param {any} remoteSocket 
 * @param {string} addressRemote The remote address to connect to.
 * @param {number} portRemote The remote port to connect to.
 * @param {Uint8Array} rawClientData The raw client data to write.
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket The WebSocket to pass the remote socket to.
 * @param {function} log The logging function.
 * @returns {Promise<void>} The remote socket.
 */
async function handleTCPOutBound(remoteSocket, addressRemote, portRemote, rawClientData, webSocket, log) {
    async function connectAndWrite(address, port) {
        /** @type {import("@cloudflare/workers-types").Socket} */
        const tcpSocket = connect({
            hostname: address,
            port: port,
        });
        remoteSocket.value = tcpSocket;
        log(`connected to ${address}:${port}`);
        const writer = tcpSocket.writable.getWriter();
        await writer.write(rawClientData); // first write, nomal is tls client hello
        writer.releaseLock();
        return tcpSocket;
    }
    const tcpSocket = await connectAndWrite(addressRemote, portRemote);

    // when remoteSocket is ready, pass to websocket
    // remote--> ws
    remoteSocketToWS(tcpSocket, webSocket, log);
}

/**
 * @param {import("@cloudflare/workers-types").WebSocket} webSocketServer
 * @param {string} earlyDataHeader for ws 0rtt
 * @param {(info: string)=> void} log for ws 0rtt
 */
function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
    let readableStreamCancel = false;
    const stream = new ReadableStream({
        start(controller) {
            webSocketServer.addEventListener('message', (event) => {
                if (readableStreamCancel) {
                    return;
                }
                const message = event.data;
                controller.enqueue(message);
            });

            // The event means that the client closed the client -> server stream.
            // However, the server -> client stream is still open until you call close() on the server side.
            // The WebSocket protocol says that a separate close message must be sent in each direction to fully close the socket.
            webSocketServer.addEventListener('close', () => {
                // client send close, need close server
                // if stream is cancel, skip controller.close
                safeCloseWebSocket(webSocketServer);
                if (readableStreamCancel) {
                    return;
                }
                controller.close();
            }
            );
            webSocketServer.addEventListener('error', (err) => {
                log('webSocketServer has error');
                controller.error(err);
            }
            );
            // for ws 0rtt
            const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
            if (error) {
                controller.error(error);
            } else if (earlyData) {
                controller.enqueue(earlyData);
            }
        },
        pull(controller) {
            // if ws can stop read if stream is full, we can implement backpressure
            // https://streams.spec.whatwg.org/#example-rs-push-backpressure
        },
        cancel(reason) {
            // 1. pipe WritableStream has error, this cancel will called, so ws handle server close into here
            // 2. if readableStream is cancel, all controller.close/enqueue need skip,
            // 3. but from testing controller.error still work even if readableStream is cancel
            if (readableStreamCancel) {
                return;
            }
            log(`ReadableStream was canceled, due to ${reason}`)
            readableStreamCancel = true;
            safeCloseWebSocket(webSocketServer);
        }
    });
    return stream;
}

/**
 * @param { ArrayBuffer} trojanBuffer 
 * @returns 
 */
function processTrojanHeader(trojanBuffer) {
    if (trojanBuffer.byteLength < 56) {
        return {
            hasError: true,
            message: 'invalid data',
        };
    }
    if (trojanBuffer.slice(0, 56) !== passwordSha224) {
        return {
            hasError: true,
            message: 'invalid user',
        };
    }

    let isUDP = false;
    const command = new Uint8Array(trojanBuffer.slice(58, 59))[0];
    // 0x01 TCP 
    // 0x03 UDP
    if (command === 1) {
    } else if (command === 3) {
        isUDP = true;
    } else {
        return {
            hasError: true,
            message: `command ${command} is not support, command 01-tcp,02-udp,03-mux`,
        };
    }
    // 1--> ipv4  addressLength =4
    // 3--> domain name addressLength=addressBuffer[1]
    // 4--> ipv6  addressLength =16
    const addressType = new Uint8Array(trojanBuffer.slice(59, 60))[0];
    let addressLength = 0;
    let addressValueIndex = 60;
    let addressValue = '';
    switch (addressType) {
        case 1:
            addressLength = 4;
            addressValue = new Uint8Array(
                trojanBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
            ).join('.');
            break;
        case 3:
            addressLength = new Uint8Array(
                trojanBuffer.slice(addressValueIndex, addressValueIndex + 1)
            )[0];
            addressValueIndex += 1;
            addressValue = new TextDecoder().decode(
                trojanBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
            );
            break;
        case 4:
            addressLength = 16;
            const dataView = new DataView(
                trojanBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
            );
            const ipv6 = [];
            for (let i = 0; i < 8; i++) {
                ipv6.push(dataView.getUint16(i * 2).toString(16));
            }
            addressValue = ipv6.join(':');
            break;
        default:
            return {
                hasError: true,
                message: `invild  addressType is ${addressType}`,
            };
    }
    if (!addressValue) {
        return {
            hasError: true,
            message: `addressValue is empty, addressType is ${addressType}`,
        };
    }
    const portBuffer = trojanBuffer.slice(addressValueIndex + addressLength, addressValueIndex + addressLength + 2);
    const portRemote = new DataView(portBuffer).getUint16(0);
    const rawDataIndex = addressValueIndex + addressLength + 4;
    return {
        hasError: false,
        addressRemote: addressValue,
        addressType,
        portRemote,
        rawDataIndex: rawDataIndex,
        isUDP,
    };
}

/**
 * @param {import("@cloudflare/workers-types").Socket} remoteSocket 
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket
 * @param {*} log 
 */
async function remoteSocketToWS(remoteSocket, webSocket, log) {
    // remote--> ws
    /** @type {ArrayBuffer | null} */
    await remoteSocket.readable.pipeTo(
        new WritableStream({
            start() { },
            /**
             * @param {Uint8Array} chunk 
             * @param {*} controller 
             */
            async write(chunk, controller) {
                if (webSocket.readyState !== WS_READY_STATE_OPEN) {
                    controller.error(
                        'webSocket.readyState is not open, maybe close'
                    );
                }
                webSocket.send(chunk);
            },
            close() {
                log(`remoteConnection!.readable is close with hasIncomingData is`);
            },
            abort(reason) {
                console.error(`remoteConnection!.readable abort`, reason);
            },
        })
    )
        .catch((error) => {
            console.error(
                `remoteSocketToWS has exception `,
                error.stack || error
            );
            safeCloseWebSocket(webSocket);
        });
}

/**
 * @param {string} base64Str 
 * @returns 
 */
function base64ToArrayBuffer(base64Str) {
    if (!base64Str) {
        return { error: null };
    }
    try {
        // go use modified Base64 for URL rfc4648 which js atob not support
        base64Str = base64Str.replace(/-/g, '+').replace(/_/g, '/');
        const decode = atob(base64Str);
        const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
        return { earlyData: arryBuffer.buffer, error: null };
    } catch (error) {
        return { error };
    }
}

/**
 * Normally, WebSocket will not has exceptions when close.
 * @param {import("@cloudflare/workers-types").WebSocket} socket
 */
function safeCloseWebSocket(socket) {
    try {
        if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
            socket.close();
        }
    } catch (error) {
        console.error('safeCloseWebSocket error', error);
    }
}

/**
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket
 * @param {(string)=> void} log 
 */
async function handleUDPOutBound(webSocket, log) {
    const transformStream = new TransformStream({
        start(controller) { },
        transform(chunk, controller) {
            // udp message 2 byte is the the length of udp data
            // TODO: this should have bug, beacsue maybe udp chunk can be in two websocket message
            for (let index = 0; index < chunk.byteLength;) {
                const lengthBuffer = chunk.slice(index, index + 2);
                const udpPakcetLength = new DataView(lengthBuffer).getUint16(0);
                const udpData = new Uint8Array(
                    chunk.slice(index + 2, index + 2 + udpPakcetLength)
                );
                index = index + 2 + udpPakcetLength;
                controller.enqueue(udpData);
            }
        },
        flush(controller) {
        }
    });

    // only handle dns udp for now
    transformStream.readable.pipeTo(new WritableStream({
        async write(chunk) {
            const resp = await fetch('https://1.1.1.1/dns-query',
                {
                    method: 'POST',
                    headers: {
                        'content-type': 'application/dns-message',
                    },
                    body: chunk,
                })
            const dnsQueryResult = await resp.arrayBuffer();
            const udpSize = dnsQueryResult.byteLength;
            // console.log([...new Uint8Array(dnsQueryResult)].map((x) => x.toString(16)));
            const udpSizeBuffer = new Uint8Array([(udpSize >> 8) & 0xff, udpSize & 0xff]);
            if (webSocket.readyState === WS_READY_STATE_OPEN) {
                log(`doh success and dns message length is ${udpSize}`);
                webSocket.send(await new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer());
            }
        }
    })).catch((error) => {
        log('dns udp has error' + error)
    });
    const writer = transformStream.writable.getWriter();
    return {
        /** @param {Uint8Array} chunk */
        write(chunk) {
            writer.write(chunk);
        }
    };
}