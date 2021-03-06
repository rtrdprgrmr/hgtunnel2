/*
Copyright (c) 2016 rtrdprgrmr

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

var net = require('net')
var crypto = require('crypto')
var http = require('http')
var url = require('url')

var remote_url = process.argv[2] || "http://wgtu2.herokuapp.com"
var local_port = process.argv[3] || 8080
var upper_proxy = process.env.upper_proxy

if (upper_proxy) {
    console.log("connecting to " + remote_url + " via " + upper_proxy)
    var obj = url.parse(upper_proxy)
    var path = remote_url
    var host = obj.hostname
    var port = obj.port || 80
} else {
    console.log("connecting to " + remote_url)
    var obj = url.parse(remote_url)
    var path = obj.path
    var host = obj.hostname
    var port = obj.port || 80
}

function http_get(headers, callback, bodies, id) {
    var l = 0
    if (bodies) {
        for (var i = 0; i < bodies.length; i++) {
            l += bodies[i].length
        }
    }
    headers['Content-Length'] = l
    headers['Connection'] = 'Keep-Alive'
    headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    headers['Pragma'] = 'no-cache'
    headers['Expires'] = '0'
    var req = http.request({
            method: 'GET',
            path: path,
            host: host,
            port: port,
            headers: headers,
        },
        completion
    )
    if (bodies) {
        for (var i = 0; i < bodies.length; i++) {
            req.write(bodies[i])
        }
    }
    req.end()
    req.on('error', function(e) {
        console.error(e)
        process.exit(1)
    })

    function completion(res) {
        if (res.statusCode != 200) {
            console.error("(" + id + ") statusCode " + res.statusCode)
            if (res.headers['x-info'] == 'session invalid') {
                console.error("session invalid")
                process.exit(1)
            }
        }
        callback(res)
    }
}

var sid
var prime = 'd8496a29582cd63be4daed4580e306a4ee1b97edebae348be8b647effe058700' +
    '9ffcec76a08cf6247e9f3a8f2e60c81efd3ec604b5071396e81801334cafa7db' // 512bits
var rq = crypto.createDiffieHellman(prime, 'hex')
rq.generateKeys()
var publicKey = rq.getPublicKey('hex')
var secret

function info_encrypt(info) {
    var encrypt = crypto.createCipher('des-cbc', secret)
    var data = encrypt.update(crypto.randomBytes(16).toString('hex'), 'hex', 'hex')
    data += encrypt.update(JSON.stringify(info), 'utf8', 'hex')
    data += encrypt.final('hex')
    return data
}

function info_decrypt(data) {
    var decrypt = crypto.createDecipher('des-cbc', secret)
    var hexstr = decrypt.update(data, 'hex', 'hex')
    hexstr += decrypt.final('hex')
    hexstr = hexstr.slice(32)
    return JSON.parse(new Buffer(hexstr, 'hex').toString('utf8'))
}

http_get({
        'x-id': '0',
        'x-info': publicKey,
    },
    function(res) {
        if (res.statusCode != 200) {
            process.exit(1)
        }
        sid = res.headers['x-id']
        secret = rq.computeSecret(res.headers['x-info'], 'hex')
        console.log("new session " + sid)
        init_server()
    },
    null, "init"
)

function init_server() {
    var server = http.createServer(handle_normal)
    server.on('connect', handle_connect)
    server.listen(local_port)
}

var maxRID = 0

function handle_normal(req, res2client) {
    var rid = 'rid' + (maxRID++)
    var up = crypto.randomBytes(32).toString('hex')
    var dn = crypto.randomBytes(32).toString('hex')
    var encrypt = crypto.createCipher('des-cbc', up)
    var decrypt = crypto.createDecipher('des-cbc', dn)
    var bodies = []
    req.on('data', function(data) {
        bodies.push(encrypt.update(data))
    })
    req.on('end', function() {
        bodies.push(encrypt.final())
        console.log("(" + rid + ") requesting to " + req.url)
            //console.log(req.headers)
        http_get({
                'x-id': sid,
                'x-info': info_encrypt({
                    type: 'normal',
                    url: req.url,
                    method: req.method,
                    headers: req.headers,
                    up: up,
                    dn: dn,
                })
            },
            completion, bodies, rid)
    })
    req.on('error', function(e) {
        console.error("(" + rid + ") request error")
        console.error(e)
        close(503)
    })

    function completion(res) {
        if (res.statusCode != 200) {
            close(res.statusCode)
            return
        }
        var info = info_decrypt(res.headers['x-info'])
        res2client.writeHead(info.statusCode, info.statusMessage, info.headers)
        console.log("(" + rid + ") response status=" + info.statusCode)
            //console.log(info.headers)
        res.on('data', function(data) {
            if (!res2client.write(decrypt.update(data))) {
                res.pause()
            }
        })
        res2client.on('drain', function() {
            res.resume()
        })
        res.on('end', function() {
            res2client.end(decrypt.final())
        })
    }

    function close(statusCode) {
        res2client.statusCode = statusCode
        res2client.end()
    }
}

var maxCID = 0

function handle_connect(req, sock, head) {
    var cid = 'cid' + (maxCID++)
    console.log("(" + cid + ") connecting to " + req.url)
    http_get({
            'x-id': sid,
            'x-info': info_encrypt({
                type: 'connect',
                cid: cid,
                url: req.url,
            })
        },
        function(res) {
            if (res.statusCode != 200) {
                close()
                return
            }
            console.log("(" + cid + ") connected")
            sock.write("HTTP/1.1 200 Connection established\r\n\r\n")
            start()
        },
        null, 'connect ' + cid
    )

    function start() {
        if (head && head.length) {
            sock.pause()
            send_up(head)
        }
        sock.on('data', function(data) {
            sock.pause()
            send_up(data)
        })
        sock.on('end', function() {
            send_end()
        })
        recv_dn()
    }

    function send_up(data) {
        var up = crypto.randomBytes(32).toString('hex')
        var encrypt = crypto.createCipher('des-cbc', up)
        var bodies = [encrypt.update(data), encrypt.final()]
        http_get({
                'x-id': sid,
                'x-info': info_encrypt({
                    type: 'up',
                    cid: cid,
                    up: up,
                })
            },
            function(res) {
                if (res.statusCode != 200) {
                    close()
                    return
                }
                sock.resume()
            },
            bodies, 'up ' + cid
        )
    }

    function send_end() {
        http_get({
                'x-id': sid,
                'x-info': info_encrypt({
                    type: 'end',
                    cid: cid,
                })
            },
            function(res) {
                if (res.statusCode != 200) {
                    close()
                    return
                }
                console.log("(" + cid + ") connection closed")
            },
            null, 'end ' + cid
        )
    }

    function recv_dn() {
        var dn = crypto.randomBytes(32).toString('hex')
        var decrypt = crypto.createDecipher('des-cbc', dn)
        http_get({
                'x-id': sid,
                'x-info': info_encrypt({
                    type: 'dn',
                    cid: cid,
                    dn: dn,
                })
            },
            function(res) {
                if (res.statusCode != 200) {
                    close()
                    return
                }
                if (res.headers['x-end'] == 'poll') {
                    recv_dn()
                    return
                }
                if (res.headers['x-end']) {
                    sock.end()
                    return
                }
                res.on('data', function(data) {
                    if (!sock.write(decrypt.update(data))) {
                        res.pause()
                    }
                })
                sock.on('drain', drain_listener)

                function drain_listener() {
                    res.resume()
                }
                res.on('end', function() {
                    sock.removeListener('drain', drain_listener)
                    sock.write(decrypt.final())
                    recv_dn()
                })
            },
            null, 'dn ' + cid
        )
    }

    function close() {
        sock.destroy()
    }
}
