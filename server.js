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

var host = process.env.OPENSHIFT_NODEJS_IP || "0.0.0.0"
var port = process.env.OPENSHIFT_NODEJS_PORT || process.env.PORT || 8000
var upper_proxy = process.env.upper_proxy

if (upper_proxy) {
    console.log("using upper proxy " + upper_proxy)
    var obj = url.parse(upper_proxy)
    var proxy_host = obj.hostname
    var proxy_port = obj.port || 80
}

var server = http.createServer(function(req, res) {
    var sid = req.headers['x-id']
    if (sid === undefined) {
        res.statusCode = 503
        res.setHeader('content-type', "text/html")
        res.write("<html><body><pre>" +
            "Your request does not include expected headers.\n\n" +
            "We can't process your request for security reason.\n\n" +
            "</pre></body></html>")
        res.end()
        return
    }
    if (sid == 0) {
        var sess = new session(req.headers['x-info'])
        sess.idle = 0
        res.statusCode = 200
        res.setHeader('x-id', sess.sid)
        res.setHeader('x-info', sess.publicKey)
        res.end()
        return
    }
    var sess = sessions[sid]
    if (!sess) {
        res.statusCode = 404
        res.setHeader('x-id', sid)
        res.setHeader('x-info', 'session invalid')
        res.end()
        return
    }
    sess.idle = 0
    res.statusCode = 200
    res.setHeader('x-id', sess.sid)
    sess.handle(req, res)
})

server.listen(port, host)

var sessions = {}

function session(key) {
    var sid = String(Math.random())
    sessions[sid] = this
    this.sid = sid
    console.log("new session " + sid)

    var prime = 'd8496a29582cd63be4daed4580e306a4ee1b97edebae348be8b647effe058700' +
        '9ffcec76a08cf6247e9f3a8f2e60c81efd3ec604b5071396e81801334cafa7db' // 512bits
    var rq = crypto.createDiffieHellman(prime, 'hex')
    rq.generateKeys()
    this.publicKey = rq.getPublicKey('hex')
    var secret = rq.computeSecret(key, 'hex')

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

    this.handle = handle

    function handle(req, res) {
        var info = info_decrypt(req.headers['x-info'])
        if (info.type == 'normal') {
            handle_normal(info, req.headers['x-body'], res)
            return
        }
        if (info.type == 'connect') {
            handle_connect(info, res)
            return
        }
        var conn = connections[info.cid]
        if (!conn) {
            res.statusCode = 404
            res.setHeader('x-id', sid)
            res.setHeader('x-info', 'connection invalid')
            res.end()
            return
        }
        if (info.type == 'up') {
            handle_up(conn, info, req.headers['x-body'], res)
            return
        }
        if (info.type == 'dn') {
            handle_dn(conn, info, res)
            return
        }
        if (info.type == 'end') {
            handle_end(conn, info, res)
            return
        }
    }

    function handle_normal(info, body, res2proxy) {
        var encrypt = crypto.createCipher('des', info.dn)
        var decrypt = crypto.createDecipher('des', info.up)
        console.log("requesting to " + info.url + " with body length=" + body.length)
            //console.log(info.headers)
        var obj = url.parse(info.url)
        var req = http.request({
                method: info.method,
                path: upper_proxy ? info.url : obj.path,
                host: upper_proxy ? proxy_host : obj.hostname,
                port: upper_proxy ? proxy_port : obj.port || 80,
                headers: info.headers,
            },
            completion)
        req.write(decrypt.update(body, 'hex'))
        req.write(decrypt.final())
        req.end()
        req.on('error', function(e) {
            console.error(e)
            res2proxy.statusCode = 400
            res2proxy.end()
        })

        function completion(res) {
            console.log("response from " + info.url + " status=" + res.statusCode)
                //console.log(res.headers)
            res2proxy.statusCode = 200
            res2proxy.setHeader('x-info', info_encrypt({
                statusCode: res.statusCode,
                statusMessage: res.statusMessage,
                headers: res.headers,
            }))
            res.on('data', function(data) {
                if (!res2proxy.write(encrypt.update(data))) {
                    res.pause()
                }
            })
            res2proxy.on('drain', function() {
                res.resume()
            })
            res.on('end', function() {
                res2proxy.write(encrypt.final())
                res2proxy.end()
            })
        }
    }

    var connections = {}
    this.connections = connections

    function handle_connect(info, res2proxy) {
        var cid = info.cid
        var conn = {
            cid: cid,
            url: info.url
        }
        connections[cid] = conn
        console.log("connecting to " + info.url)
        if (upper_proxy) {
            var req = http.request({
                method: 'CONNECT',
                path: info.url,
                host: proxy_host,
                port: proxy_port,
                headers: {
                    'Connection': 'Keep-Alive',
                    'Content-Length': 0
                }
            })
            req.end()
            req.on('connect', function(res, sock) {
                conn.sock = sock
                res2proxy.statusCode = 200
                res2proxy.end()
            })
            req.on('error', function(e) {
                console.error(e)
                if (!res2proxy.finished) {
                    res2proxy.statusCode = 404
                    res2proxy.end()
                }
            })
        } else {
            var obj = url.parse("http://" + info.url)
            var sock = net.connect(obj.port || 80, obj.hostname, function() {
                conn.sock = sock
                res2proxy.statusCode = 200
                res2proxy.end()
            })
            sock.on('error', function(e) {
                console.error(e)
                if (!res2proxy.finished) {
                    res2proxy.statusCode = 404
                    res2proxy.end()
                }
            })
        }
    }

    function handle_up(conn, info, body, res2proxy) {
        var sock = conn.sock
        var decrypt = crypto.createDecipher('des', info.up)
        sock.write(decrypt.update(body, 'hex'))
        sock.write(decrypt.final())
            //TODO flow control
        res2proxy.statusCode = 200
        res2proxy.end()
    }

    function handle_end(conn, info, res2proxy) {
        var sock = conn.sock
        sock.end()
        res2proxy.statusCode = 200
        res2proxy.end()
    }

    function handle_dn(conn, info, res2proxy) {
        var sock = conn.sock
        var encrypt = crypto.createCipher('des', info.dn)
        sock.once('data', data_listener)
        sock.once('end', end_listener)
        sock.resume()

        function data_listener(data) {
            sock.pause()
            sock.removeListener('end', end_listener)
            var body1 = encrypt.update(data)
            var body2 = encrypt.final()
            res2proxy.setHeader('Content-Length', body1.length + body2.length)
            res2proxy.statusCode = 200
            res2proxy.write(body1)
            res2proxy.write(body2)
            res2proxy.end()
        }

        function end_listener() {
            res2proxy.setHeader('x-end', 'true')
            res2proxy.statusCode = 200
            res2proxy.end()
        }
    }
}

function patrol() {
    for (sid in sessions) {
        var sess = sessions[sid]
        sess.idle++
            if (sess.idle < 10) continue
        console.log("expiring session " + sid)
        delete(sessions[sid])
        for (cid in sess.connections) {
            var conn = sess.connections[cid]
            conn.close()
        }
    }
}

setInterval(patrol, 100000)