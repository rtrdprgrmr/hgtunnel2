tunneling http/https requests via http-get
==========================================

Diagram
-------

--(http/https)--> proxy.js --(httpGET)--> server.js --(http/https)-->

Optionally upper proxy server can be inserted.

proxy.js --(httpGET)--> upper_proxy --(httpGET)--> server.js

proxy.js acts as a http/https proxy server.

Usage
-----

```sh
export upper_proxy="http://proxy-ip:proxy-port"
node proxy [remote_url [local_port]]
```

Stupid Example
--------------

```sh
node proxy 8080 &
curl --proxy http://localhost:8080 https://www.google.com
```
