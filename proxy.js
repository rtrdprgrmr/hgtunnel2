/*
Copyright (c) 2016 rtrdprgrmr

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

var net=require('net')
var crypto=require('crypto')
var http=require('http')
var url=require('url')

var local_port=process.argv[2] || 8080
var remote_url=process.argv[3] || "http://wgtu.herokuapp.com"
var upper_proxy=process.env.upper_proxy

if(upper_proxy){
	console.log("connecting to "+remote_url+" via "+upper_proxy)
	var obj=url.parse(upper_proxy)
	var path=remote_url
	var host=obj.hostname
	var port=obj.port || 80
}
else{
	console.log("connecting to "+remote_url)
	var obj=url.parse(remote_url)
	var path=obj.path
	var host=obj.hostname
	var port=obj.port || 80
}

function http_get(headers, callback){
	headers['Connection']='Keep-Alive'
	headers['Cache-Control']='no-cache, no-store, must-revalidate'
	headers['Pragma']='no-cache'
	headers['Expires']='0'
	var req=http.request({
			method: 'GET',
			path: path,
			host: host,
			port: port,
			headers: headers,
		},
		completion
	)
	req.end()
	req.on('error', function(e){
		console.error(e)
		process.exit(1)
	})
	function completion(res){
		if(res.statusCode!=200){
			console.error("statusCode "+res.statusCode)
			if(res.headers['x-info']==='session invalid'){
				console.error("session invalid")
				process.exit(1)
			}
		}
		callback(res)
	}
}

var sid
var prime = 'd8496a29582cd63be4daed4580e306a4ee1b97edebae348be8b647effe058700'
			+'9ffcec76a08cf6247e9f3a8f2e60c81efd3ec604b5071396e81801334cafa7db' // 512bits
var rq=crypto.createDiffieHellman(prime, 'hex')
rq.generateKeys()
var publicKey=rq.getPublicKey('hex')
var secret

function info_encrypt(info){
	var encrypt=crypto.createCipher('des-cbc', secret)
	var data=encrypt.update(crypto.randomBytes(16).toString('hex'), 'hex', 'hex')
	data+=encrypt.update(JSON.stringify(info), 'utf8', 'hex')
	data+=encrypt.final('hex')
	return data
}

function info_decrypt(data){
	var decrypt=crypto.createDecipher('des-cbc', secret)
	var hexstr=decrypt.update(data, 'hex', 'hex')
	hexstr+=decrypt.final('hex')
	hexstr=hexstr.slice(32)
	return JSON.parse(new Buffer(hexstr, 'hex').toString('utf8'))
}

http_get({
		'x-id': '0',
		'x-info': publicKey,
	},
	function(res){
		if(res.statusCode!=200){
			process.exit(1)
		}
		sid=res.headers['x-id']
		secret=rq.computeSecret(res.headers['x-info'], 'hex')
		console.log("new session "+sid)
		init_server()
	}
)

function init_server(){
	var server=http.createServer(handle_normal)
	server.on('connect', handle_connect)
	server.listen(local_port)
}

function handle_normal(req, res2client){
	var up=crypto.randomBytes(32).toString('hex')
	var dn=crypto.randomBytes(32).toString('hex')
	var encrypt=crypto.createCipher('des', up)
	var decrypt=crypto.createDecipher('des', dn)
	var body=''
	req.on('data', function(data){
		body += encrypt.update(data, 'binary', 'hex');
	})
	req.on('end', function(){
		body += encrypt.final('hex');
		console.log("requesting to "+req.url)
		http_get({
				'x-id': sid,
				'x-info': info_encrypt({
					type: 'normal',
					url: req.url,
					method: req.method,
					headers: req.headers,
					up: up,
					dn: dn,
				}),
				'x-body': body
			},
			completion)
	})
	function completion(res){
		if(res.statusCode!=200) return
		var info=info_decrypt(res.headers['x-info'])
		res2client.writeHead(info.statusCode, info.statusMessage, info.headers)
		res.on('data', function(data){
			if(!res2client.write(decrypt.update(data))){
				res.pause()
			}
		})
		res2client.on('drain', function(){
			res.resume()
		})
		res.on('end', function(){
			res2client.end(decrypt.final())
		})
	}
}

var maxCID=0
function handle_connect(req, sock, head){
	var cid=maxCID++
	var up=crypto.randomBytes(32).toString('hex')
	var dn=crypto.randomBytes(32).toString('hex')
	var encrypt=crypto.createCipher('des', up)
	var decrypt=crypto.createDecipher('des', dn)
	console.log("connecting to "+req.url)
	console.log(req.headers)
	console.log(head)
	http_get({
			'x-id': sid,
			'x-info': info_encrypt({
				type: 'connect',
				cid: cid,
				url: req.url,
				method: req.method,
				headers: req.headers,
				up: up,
				dn: dn,
				head: head,
			})
		},
		function(res){
			if(res.statusCode!=200) return
			console.log("connected to "+req.url)
			sock.write("HTTP/1.1 200 Connection established\r\n\r\n")
			start()
		}
	)

	function start(){
		sock.on('data', function(data){
			sock.pause()
			var body = encrypt.update(data)
			send_up(body)
		})
		sock.on('end', function(){
			var body = encrypt.final()
			send_up(body)
		})
	}

	function send_up(data){
		var body = encrypt.update(data)
		http_get({
				'x-id': sid,
				'x-info': info_encrypt({
					cid: cid,
					type: 'up',
				})
			},
			function(res){
				if(res.statusCode!=200){
					console.log("statusCode "+res.statusCode+" on "+tgt)
					close()
					return
				}
				encrypt.resume()
			},
			data
		)
	}

	encrypt.on('end', function(){
		http_get({
				'x-id': sid,
				'x-info': info_encrypt({
					cid: cid,
					type: 'end',
				})
			},
			function(res){
				console.log("up end "+tgt)
				if(res.statusCode!=200){
					console.log("statusCode "+res.statusCode+" on "+tgt)
					close()
					return
				}
			}
		)
	})

	function recv_dn(){
		http_get({
				'x-id': sid,
				'x-info': info_encrypt({
					cid: cid,
					type: 'dn',
				})
			},
			function(res){
				if(res.statusCode!=200){
					console.log("statusCode "+res.statusCode+" on "+tgt)
					close()
					return
				}
				if(res.headers['x-info']){
					var info=info_decrypt(res.headers['x-info'])
					if(info.statusCode) {
						sock.writeHead(info.statusCode, info.statusMessage, info.headers)
						//console.log(info.statusCode, info.statusMessage, info.headers)
					}
				}
				res.on('data', function(data){
					console.log("dn "+data.length+" "+tgt)
					decrypt.write(data)
				})
				res.once('end', function(data){
					if(info && info.end){
						console.log("dn end "+tgt)
						decrypt.end()
						return
					}
					recv_dn()
				})
			}
		)
	}

}
