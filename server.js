/*
Copyright (c) 2016 rtrdprgrmr

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

var host=process.env.OPENSHIFT_NODEJS_IP || "0.0.0.0"
var port=process.env.OPENSHIFT_NODEJS_PORT || process.env.PORT || 8000

var net=require('net')
var crypto=require('crypto')
var http=require('http')
var url=require('url')

var server=http.createServer(function(req, res){
	var sid=req.headers['x-id']
	if(sid===undefined){
		res.statusCode=503
		res.setHeader('content-type', "text/html")
		res.write("<html><body><pre>"
		+"Your request does not include expected headers.\n\n"
		+"We can't process your request for security reason.\n\n"
		+"</pre></body></html>")
		res.end()
		return
	}
	if(sid==0){
		var sess=new session(req.headers['x-info'])
		sess.idle=0
		res.statusCode=200
		res.setHeader('x-id', sess.sid)
		res.setHeader('x-info', sess.publicKey)
		res.end()
		return
	}
	var sess=sessions[sid]
	if(!sess){
		res.statusCode=404
		res.setHeader('x-id', sid)
		res.setHeader('x-info', 'session invalid')
		res.end()
		return
	}
	sess.idle=0
	res.statusCode=200
	res.setHeader('x-id', sess.sid)
	sess.handle(req, res)
})

server.listen(port, host)

var sessions={}

function session(key){
	var sid=String(Math.random())
	sessions[sid]=this
	this.sid=sid
	console.log("new session "+sid)

	var prime = 'd8496a29582cd63be4daed4580e306a4ee1b97edebae348be8b647effe058700'
				+'9ffcec76a08cf6247e9f3a8f2e60c81efd3ec604b5071396e81801334cafa7db'; // 512bits
	var rq=crypto.createDiffieHellman(prime, 'hex')
	rq.generateKeys()
	this.publicKey=rq.getPublicKey('hex')
	var secret=rq.computeSecret(key, 'hex')

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

	this.handle = handle
	function handle(req, res){
		var info=info_decrypt(req.headers['x-info'])
		if(info.type=='normal'){
			handle_normal(info, req.headers['x-body'], res)
		}
		else if(info.type=='connect'){
		}
		else if(info.type=='up'){
		}
		else if(info.type=='dn'){
		}
	}

	function handle_normal(info, body, res2proxy){
		var encrypt=crypto.createCipher('des', info.dn)
		var decrypt=crypto.createDecipher('des', info.up)
		console.log("connecting to "+info.url)
		var obj=url.parse(info.url)
		var req=http.request({
				method: info.method,
				path: obj.path,
				host: obj.hostname,
				port: obj.port||80,
				headers: info.headers,
			},
			completion)
		req.write(decrypt.update(body, 'hex'))
		req.end(decrypt.final())
		req.on('error', function(){
			res2proxy.statusCode=400
			res2proxy.end()
		})
		function completion(res){
			res2proxy.setHeader('x-info', info_encrypt({
				statusCode: res.statusCode,
				statusMessage: res.statusMessage,
				headers: res.headers,
			}))
			res.on('data', function(data){
				var b = encrypt.update(data);
				if(!res2proxy.write(b)){
					res.pause()
				}
			})
			res2proxy.on('drain', function(){
				res.resume()
			})
			res.on('end', function(){
				var b = encrypt.final();
				res2proxy.end(b);
			})
		}
	}






/*
		var conn=connections[info.cid]
		if(!conn){
			res.statusCode=404
			res.setHeader('x-id', sid)
			res.setHeader('x-info', 'connection invalid')
			res.end()
			return
		}
		conn.handle(req, res, info)
	}
	this.handle=handle

	var connections={}
	this.connections=connections

	function connection(info, callback){
		var cid=info.cid
		connections[cid]=this
		this.cid=cid

		var encrypt=crypto.createCipher('des', info.dn)
		var decrypt=crypto.createDecipher('des', info.up)
		encrypt.pause()

		// node may fire 'end' event in spite of pause state
		var encrypt_ended=false
		encrypt.on('end', function(){
			encrypt_ended=true
		})

		var type=info.type
		var tgt=info.tgt
		console.log("connecting to "+tgt)
		if(type=='connect'){
			var obj=url.parse("http://"+tgt)
			var sock=net.connect(obj.port||80, obj.hostname, function(){
				decrypt.pipe(sock)
				sock.pipe(encrypt)
				callback(200)
			})
			sock.on('error', function(){
				callback(404)
				close()
			})
		}
		if(type=='normal'){
			var res_statusCode
			var res_statusMessage
			var res_headers
			var obj=url.parse(tgt)
			var sock=http.request({
				method: info.method,
				host: obj.hostname,
				port: obj.port||80,
				path: obj.path,
				headers: info.headers,
			},
			function(res){
				res_statusCode=res.statusCode
				res_statusMessage=res.statusMessage
				res_headers=res.headers
				res.pipe(encrypt)
				res.on('error', function(){
					close()
				})
			})
			decrypt.pipe(sock)
			callback(200)
			sock.on('error', function(){
				close()
			})
		}

		function handle(req, res, info){
			if(info.type=='end'){
				console.log("up end "+tgt)
				decrypt.final('hex')
				res.statusCode=200
				res.setHeader('x-id', sid)
				res.end()
				half_close()
				return
			}
			if(info.type=='up'){
				var body=req.headers['x-body']
				if(body){
					var data=new Buffer(body, 'hex')
					console.log("up "+data.length+" "+tgt)
					decrypt.write(data)
				}
				req.on('data', function(data){
					console.log("up "+data.length+" "+tgt)
					decrypt.write(data)
				})
				req.once('end', function(){
					res.statusCode=200
					res.setHeader('x-id', sid)
					res.end()
				})
				return
			}
			if(info.type=='dn'){
				var setup_headers=function(len){
					res.statusCode=200
					res.setHeader('content-length', len)
					res.setHeader('x-id', sid)
					if(res_statusCode){
						res.setHeader('x-info', info_encrypt({
							statusCode: res_statusCode,
							statusMessage: res_statusMessage,
							headers: res_headers,
							end: (len==0)
						}))
						res_statusCode=undefined
					}else if(len==0){
						res.setHeader('x-info', info_encrypt({
							end: true
						}))
					}
				}
				var data_listener=function(data){
					if(data.length==0) return
					console.log("dn "+data.length+" "+tgt)
					encrypt.pause()
					encrypt.removeListener('end', end_listener)
					setup_headers(data.length)
					res.write(data)
					res.end()
				}
				var end_listener=function(){
					console.log("dn end "+tgt)
					encrypt.removeListener('data', data_listener)
					setup_headers(0)
					res.end()
					half_close()
				}
				if(encrypt_ended){
					end_listener()
					return
				}
				encrypt.once('data', data_listener)
				encrypt.once('end', end_listener)
				encrypt.resume()
				return
			}
			res.statusCode=404
			res.end()
		}
		this.handle=handle

		var half_close_count=0
		function half_close(){
			half_close_count++
			if(half_close_count==2){
				close()
			}
		}
		var closed=false
		function close(){
			if(closed) return
			closed=true
			console.log("connection closed "+tgt)
			decrypt.final('hex')
			sock.destroy()
			delete(connections[cid])
		}
		this.close=close
	}
}

function patrol(){
	for(sid in sessions){
		var sess=sessions[sid]
		sess.idle++
		if(sess.idle<10) continue
		console.log("expiring session "+sid)
		delete(sessions[sid])
		for(cid in sess.connections){
			var conn=sess.connections[cid]
			conn.close()
		}
	}
}

setInterval(patrol, 100000)
*/
}
