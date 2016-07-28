/*
Copyright (c) 2016 rtrdprgrmr

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

var net = require('net')
var http = require('http')
var url = require('url')

var tgt = process.argv[2]
var local_port = process.argv[3] || '8888'
var proxy = process.env.http_proxy

if (!tgt || !proxy) {
    console.log("usage:\texport http_proxy=http://proxy-ip:proxy-port")
    console.log("\tnode client target-ip:target-port [local_port]")
    process.exit(1)
}

var server = net.createServer(function(sock) {
    console.log("connecting to " + proxy)
    var obj = url.parse(proxy)
    var host = obj.hostname
    var port = obj.port || 80

    var req = http.request({
        method: 'CONNECT',
        path: tgt,
        host: host,
        port: port,
        headers: {
            'Connection': 'Keep-Alive',
            'Content-Length': 0
        }
    })
    req.end()
    req.on('connect', function(res, svrSock) {
        console.log("connected")
        sock.pipe(svrSock)
        svrSock.pipe(sock)

        svrSock.on('error', function(e) {
            console.log("server error " + e)
        })
    })
    req.on('error', function(e) {
        console.log("request error " + e)
    })
    sock.on('error', function(e) {
        console.log("client error " + e)
    })
})

server.listen(local_port)