一步一Web
====

> 本文尝试使用Rust构建一个简单的Hello world服务程序。

## 仅使用标准库的简易Web服务器

Rust的标准库提供了很多方便的基础组件：socket的操作、线程的操作、带缓存的读写操作等，这几个点，可以拿出来构建一个简易的Web程序。

### 从简易的每个链接启动一个线程的开始

在很久以前，在建立一个Web服务器，经常会看到这种的处理方式。每accept到一个socket，就新建一个线程来处理。这是一个简易的做法。

```rust
use std::net::{TcpListener, TcpStream};

fn main() {
    let listener = TcpListener::bind("127.0.0.1:5000")?;

    loop {
        let (socket, remote_addr) = listener.accept()?;

        std::thread::spawn(move || match handle_conn(socket, remote_addr) {
            Ok(_) => {
                println!("handle conn done");
            }
            Err(e) => {
                println!("handle conn error: {:?}", e);
            }
        });
    }
}
```

### 看一下HTTP协议

HTTP的简单说明可以看一下这个文档：[MDN上的说明](https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Overview)。


首先从请求（Request）的出发：

摘抄如下：
>![请求的说明](https://media.prod.mdn.mozit.cloud/attachments/2016/08/09/13687/5d4c4719f4099d5342a5093bdf4a8843/HTTP_Request.png)
>请求由以下元素组成：
>    一个HTTP的method，经常是由一个动词像GET, POST 或者一个名词像OPTIONS，HEAD来定义客户端的动作行为。通常客户端的操作都是获取资源（GET方法）或者发送HTML form表单值（POST方法），虽然在一些情况下也会有其他操作。
>    要获取的资源的路径，通常是上下文中就很明显的元素资源的URL，它没有protocol （http://），domain（developer.mozilla.org），或是TCP的port（HTTP一般在80端口）。
>    HTTP协议版本号。
>    为服务端表达其他信息的可选头部headers。
>    对于一些像POST这样的方法，报文的body就包含了发送的资源，这与响应报文的body类似。

基于这个简易说明，现在让我们添加HTTP的请求的处理吧。

```rust
#[derive(Debug, Clone, Default)]
struct Request {
    method: String,
    target: String,
    version: String,
    headers: Headers,
    body: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
struct Headers {
    inner: HashMap<String, Vec<String>>,
}
```

可以看到，我们是依照协议的定义来进行我们的结构体定义：method、target、version字段呈现第一行的请求信息；headers保存请求头的信息，这里是一个简易的的HashMap；body是一个可有可无的数据，在我们的实现中这里基本是忽略了它的。

### 带缓存的读请求

那么是要怎样从socket里面的读取信息来填充我们`Request`呢？Rust提供了一个很好用的带缓存的的数据读写组件：[BufReader](https://doc.rust-lang.org/std/io/struct.BufReader.html)和[BufWriter](https://doc.rust-lang.org/std/io/struct.BufWriter.html)。它们内部带了缓存，这样我们不用为每次read的中断和等待数据而烦恼，为我们的读写带来很多的便利。

`BufReader::read_line`: 直接读出一行文本，这里在我们读取请求头时很方便。

`BufReader::read_exact`: 读出所需要长度的数据。

利用read_line读取header:

```rust
fn read_from(reader: &mut BufReader<TcpStream>) -> Result<Headers> {
        let mut headers: HashMap<String, Vec<String>> = HashMap::new();

        loop {
            let mut line = String::new();
            // 按行读取
            reader.read_line(&mut line)?;

            let line = line.trim_end();

            if line.is_empty() {
                break;
            }
            // 以`:`切割
            let parts: Vec<&str> = line.splitn(2, ':').collect();
            if parts.len() != 2 {
                return Err(error_message("header line not ok"));
            }

            let key = parts[0].to_string();
            let value = parts[1].trim_start().to_string();
            // 添加到HashMap
            headers
                .entry(key)
                .and_modify(|values| values.push(value.clone()))
                .or_insert(vec![value]);
        }

        let headers = Headers { inner: headers };

        Ok(headers)
    }
```

**注意：这里的读取一行是按`\n`分割，而不是按标准的`\r\n`处理**

可以看到，在这个读取HTTP的Header的函数中，整个流程很清晰，不断的读取一行，分割解析保存。
在`BufReader`的内置缓存帮助下，这里很简单的就可以读取socket的内容了。

在典型的read操作，在Rust、C语言中，直接读socket，都是要自己维护buffer，而且需要处理读取被中断的情况：

```C
#define E_OK 0
#define E_ERR -1
#define E_EOF -2
#define BUF_SIZE 8 * 1024

// 注意：返回的buf需要调用者手动free！
void* read_expect(int fd, size_t expect, size_t* buf_size, int* ret)
{
    size_t total = 0;
    size_t rest = expect;
    void* buf = malloc(expect);

    *ret = E_OK;

    while (rest) {
        size_t nread;
        char* tmp = (char*)buf;

        nread = read(fd, tmp + total, rest);
        if (nread == -1 && errno != EINTR) {
            *ret = E_ERR;
            break;
        }

        if (nread == 0) {
            *ret = E_EOF;
            break;
        }

        total += nread;
        rest -= nread;
    }

    *buf_size = total;

    return buf;
}
```

可以说，`BufReader`这一类的方法使整个流程的处理便利了很多。

### 返回响应

>![响应的说明](https://media.prod.mdn.mozit.cloud/attachments/2016/08/09/13691/58390536967466a1a59ba98d06f43433/HTTP_Response.png)

同样的，根据HTTP协议定义我们的响应：

```rust
#[derive(Debug, Clone)]
struct Response {
    version: String,
    status_code: u16,
    status_text: String,
    headers: Headers,
    body: Option<Vec<u8>>,
}
```

在我们简易实现中，一切都从简，不做读取Response的操作，只返回它。

```rust
fn write_to(&self, writer: &mut BufWriter<TcpStream>) -> Result<()> {
    self.write_status_line(writer)?;

    self.write_headers(writer)?;

    self.write_connection_close(writer)?;

    self.write_content_length(writer)?;

    self.write_empty_line(writer)?;

    self.write_body(writer)?;

    Ok(())
}
```

同样地，依然是使用`BufWrite`来进行写操作。

### 看一下最后的效果

[完整的代码](https://github.com/zzzdong/one-step-one-web/tree/master/stdthread-web)

```bash
git cloen https://github.com/zzzdong/one-step-one-web

cd one-step-one-web/stdthread-web

cargo run
```

`curl -i http://127.0.0.1:5000/` 或者打开浏览器看看效果


## 初见多路复用

在前面，我们使用了每个链接一个线程的方式，这样处理，在高并发的时候，会导致系统中出现多个线程，占用的系统资源高，影响性能。

在历史的发展进程，从C10K等问题中，应用多路复用的处理方式越来越多了，Linux（epoll）、FreeBSD（kqueue）等。

在Rust的领域，我们可以看到[mio](https://github.com/tokio-rs/mio)这个优秀的封装库。

### 简述事件驱动

事件驱动的实现一般会有以下的特征：

1. 有一个东西提供对事件的监控，事件可能是：socket可读（readable）、可写（writeable）、有新链接进来。
2. 当事件发生时，可以知道发生事件的来源（source）。
3. 可以动态变更要监控的事件来源。

这里尝试用简单的语言描述下应用mio这些事件驱动的套路。
所以先建立一个链接监听指定端口，监听该socket的有新stream进入的事件，在新stream连接成功后，把这个stream也加入监听的队列中。
对于每个被监控的stream，我们关注stream的可读、可写事件：

* 当可读时候，读完stream中的数据并尝试解析读到的数据；在请求的数据已经完成被解析完成后，就可以处理请求的数据，做出相应的处理。
* 当可写时候，我们尝试把要返回给stream对端的数据发出去，直到发完为止。

废话少说，献上事件循环时的处理：

```rust
fn run_loop(&mut self) -> io::Result<()> {
    let mut events = Events::with_capacity(EVENT_SIZE);

    loop {
        self.poller.poll(&mut events, None)?;

        let mut to_removed = Vec::new();
        let mut new_conns = Vec::new();
		// 处理每一个事件
        for event in &events {
            // 根据事件token取出链接
            let token = event.token();
            let stream = { self.conns.get_mut(&token).unwrap() };
			
            // 处理读事件
            if event.is_readable() {
                match stream.on_readable() {
                    Ok(State::Accepted(conn)) => {
                        for c in conn {
                            new_conns.push(c);
                        }
                    }
                    Ok(State::Done) => {
                        to_removed.push(token);
                    }
                    Ok(State::Running) => {}
                    Err(e) => {
                        println!("read stream error: {:?}", e);
                        to_removed.push(token);
                    }
                }
            }
            // 处理写事件
            if event.is_writable() {
                match stream.on_writable() {
                    Ok(State::Done) => {
                        to_removed.push(token);
                    }
                    Err(e) => {
                        println!("write stream error: {:?}", e);
                        to_removed.push(token);
                    }
                    _ => {}
                }
            }
        }

        for token in to_removed {
            self.conns.remove(&token);
        }

        for c in new_conns {
            let mut conn = HttpConn::new(c);

            let token = self.register(&mut conn, Interest::READABLE.add(Interest::WRITABLE))?;

            self.conns.insert(token, Box::new(conn));
        }
    }
}
```

****
其实这里使用mio写起来要比直接用epoll来麻烦，因为epoll里面的`epoll_event.data`可以直接保存结构体的指针，从而使拿到event的时候直接取出上下文，而mio事件时拿到的是token，要用token从HashMap中拿出对应的上下文。
****

### 读取请求数据

另外由于少了`BufReader`这些的辅助，我们需要自己的缓存，读取的操作变得繁重起来。和前面的举例的`read_exact`很像，需要不断的循环读。

```rust
fn on_readable(&mut self) -> io::Result<State> {
    let mut len;

    loop {
        let old_len = self.r_buf.len();
        len = old_len + BUF_SIZE;

        self.r_buf.resize(len, 0x00);

        match self.stream.read(&mut self.r_buf[old_len..]) {
            Ok(nread) => len = old_len + nread,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(e),
        };
    }

    self.r_buf.resize(len, 0);

    match self.req_codec.decode(&mut self.r_buf)? {
        Some(req) => {
            println!("=> {:?}", req);
            let mut resp = Response::ok();
            resp.set_body("<h1>Hello, world</h1>");

            let mut codec = ResponseCodec;
            codec.encode(&resp, &mut self.w_buf)?;
            self.flush()?;
            self.set_finished();
        }
        None => return Ok(State::Running),
    }

    Ok(State::Running)
}
```

每一次可读的事件发生时，进入了on_readable的处理。我们只能使用自己内部缓存，每次尝试读取尽可能多的数据，当读取了数据之后，就去尝试解析请求的内容。当整个请求都接收完成之后，就可以做出响应，返回数据。

### 基于状态机解析数据

同样的，我们需要换一个方式来进行请求的解码。

```rust
fn parse_request(&mut self, buf: &mut BytesMut) -> io::Result<Option<()>> {
    loop {
        match self.state {
            RequestState::RequestLine => match self.parse_request_line(buf)? {
                Some(_offset) => self.state = RequestState::Headers,
                None => return Ok(None),
            },
            RequestState::Headers => match self.headers.parse_headers(buf)? {
                Some(_offset) => match self.headers.get(HEADER_CONTENT_LENGTH) {
                    Some(length) => {
                        let len = length
                            .last()
                            .ok_or_else(|| error_message("content-length error"))?;
                        let len = len
                            .parse::<usize>()
                            .map_err(|e| error_message("content-length error"))?;
                        self.state = RequestState::Body(BodyMode::Lengthed(len))
                    }
                    None => self.state = RequestState::Body(BodyMode::None),
                },
                None => return Ok(None),
            },
            RequestState::Body(ref mode) => match mode {
                // TODO: add receive body
                BodyMode::None => self.state = RequestState::Done,
                BodyMode::Lengthed(len) => {
                    let len = *len;
                    // wait all body data
                    if buf.len() < len {
                        return Ok(None);
                    } else {
                        let body = buf[0..len].to_vec();
                        buf.advance(len);
                        self.body = Some(body);
                        self.state = RequestState::Done
                    }
                }
                BodyMode::Chunked => unimplemented!(),
            },
            RequestState::Done => {}
        };

        if self.state == RequestState::Done {
            return Ok(Some(()));
        }
    }
}
```

这里是由状态来控制整个流程:
```
RequestState::RequestLine -> RequestState::Headers -> RequestState::Body -> RequestState::Done
```
在成功读到一个状态的数据后，可以跳转到下一个状态继续操作，都完成就是Done。
其实可以考虑不利用状态来判断区分当前的流程，每次都从头读写，但是这样在网络较差的情况下会出现多次回溯已处理的数据。


### 事件驱动的写数据

同样的，我们利用BytesMut作为缓存，把响应（Response）一股脑的写进入。

```rust
fn write_response(&self, buf: &mut BytesMut) -> io::Result<()> {
    self.write_status_line(buf)?;

    self.write_headers(buf)?;

    self.write_connection_close(buf)?;

    self.write_content_length(buf)?;

    self.write_empty_line(buf)?;

    self.write_body(buf)?;

    Ok(())
}
```

然后调用的`flush`来触发数据的写入。
```rust
fn flush(&mut self) -> io::Result<()> {
    if self.w_buf.len() > 0 {
        let nwrite = match self.stream.write(&self.w_buf[..]) {
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => 0,
            Err(e) => return Err(e),
        };
        self.w_buf.advance(nwrite);
    }

    Ok(())
}
```

这样就可以依赖于可读事件的来不断写了。
```rust
fn on_writable(&mut self) -> io::Result<State> {
    if self.w_buf.len() > 0 {
        let nwrite = self.stream.write(&self.w_buf[..])?;
        self.w_buf.advance(nwrite);
    }

    if self.finished && self.w_buf.len() == 0 {
        return Ok(State::Done);
    }

    Ok(State::Running)
}
```

### 看一下效果

[完整的代码](https://github.com/zzzdong/one-step-one-web/tree/master/mio-web)

```bash
cd one-step-one-web/mio-web

cargo run
```

`curl -i http://127.0.0.1:5000/` 或者打开浏览器看看效果

## 走向async

在经历了上一段的mio的实现后，总感觉脑子有些不够用。因为在使用标准库`BufReader`的实现中，我们的流程很清晰，一步步，一行行的读数据就可以了。
但是不用着急，`Rust`的领域中，有这么一个优秀的async的库可以满足你的希望，那就是[async-std](https://github.com/async-rs/async-std)。它提供了标准库的async实现，让人们可以享受Rust的`async`/`await` 语法。

### 类似标准库中的概念

先上代码：
```rust
use async_std::net::{TcpListener, TcpStream};
use async_std::prelude::*;
use async_std::task;

fn main() -> Result<()> {
    let addr = DEFAULT_ADDR;

    task::block_on(async {
        let listener = TcpListener::bind(addr).await?;
        println!("Listening on {}", listener.local_addr()?);

        let mut incoming = listener.incoming();

        while let Some(stream) = incoming.next().await {
            let stream = stream?;
            task::spawn(async {
                process(stream).await.unwrap();
            });
        }
        Ok(())
    })
}
```

async_std::task替代之前的thread，不断的accept一个stream，再spawn任务给执行器。
在会阻塞的地方，走的是`.await`来做异步。

### 极其简单的转换

async-std提供了`BufReader`和`BufWriter`，使用的方法和标准库里面的一样，只要加上`async`和 `.await`就可以了。

```rust
async fn read_from(reader: &mut BufReader<TcpStream>) -> Result<Request> {
        let (method, target, version) = Self::read_request_line(reader).await?;

        let headers = Self::read_header(reader).await?;

        let mut req = Request {
            method,
            target,
            version,
            headers,
            body: None,
        };

        req.read_body(reader).await?;

        Ok(req)
    }
```

### 就是这么简单的效果

[完整的代码](https://github.com/zzzdong/one-step-one-web/tree/master/async_std-web)

```bash
cd one-step-one-web/async_std-web

cargo run
```

`curl -i http://127.0.0.1:5000/` 或者打开浏览器看看效果

## 套用一下异步框架

在基于网络的协议的实现中，经常是要做协议的编解码，即接收到数据是解析为我们的Request，在响应时把Reponse编码为低一层的数据，再发送出去。
那么这样常见的东西，有没有方便的套路来借用一下呢，Rust领域中的[`tokio-codec`](https://docs.rs/tokio-util/0.3.1/tokio_util/codec/index.html)就是拿来辅助干这事情的。


### 既视感满满的主入口

作为Rust在async方面的双巨头之一（另一个是`async-std`），`tokio`的使用也是极其方便。
```rust
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = DEFAULT_ADDR;
    let mut listener = TcpListener::bind(addr).await?;

    loop {
        let (socket, _) = listener.accept().await?;

        tokio::spawn(async move {
            if let Err(e) = handle_conn(socket).await {
                println!("handle_conn failed; err = {:?}", e);
            }
        });
    }
}
```

是不是有种熟悉感呢，对的，这里和`async-std`的主入口是类似的。

### 编解码处理的抽象

codec在处理时，自动缓冲读到的数据，给协议解析用。

```rust
#[derive(Debug, Clone, Default)]
struct RequestDecoder(Request);

impl Decoder for RequestDecoder {
    type Item = Request;
    type Error = std::io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self.0.parse_request(src)? {
            Some(_) => {
                let req = Request::default();
                let req = std::mem::replace(&mut self.0, req);
                Ok(Some(req))
            }
            None => Ok(None),
        }
    }
}
```

同时在编码时，把数据编码为二进制数据，在可以写的时候返回。

```rust
#[derive(Debug, Clone, Default)]
struct ResponseEncoder;

impl Encoder<Response> for ResponseEncoder {
    type Error = std::io::Error;

    fn encode(&mut self, item: Response, dst: &mut BytesMut) -> Result<(), Self::Error> {
        item.write_response(dst)
    }
}
```


### 乏味的编程

在编解码器的辅助，数据的读、写都是自动的，我们要做的只是实现协议的解析和编码操作。
所以偷懒的机会又来了，直接把之前`mio-web`里面解析和编码部分拿过来用，因为它里面也是使用`BytesMut`来做缓存的。

整体下来，可以看到对比`mio-web`时是少了很多行。

### 懒得一看的效果

[完整的代码](https://github.com/zzzdong/one-step-one-web/tree/master/tokio_codec-web)

```bash
cd one-step-one-web/tokio_codec-web

cargo run
```

`curl -i http://127.0.0.1:5000/` 或者打开浏览器看看效果

## 站在巨人的肩膀上

前面的都是我们手动写HTTP解析，且不说很多部分(body等)我们没有处理、很多的解析还都是随意简化的，没有严格处理、各种的错误时也是没有处理。
要是想登上一下严肃一点的舞台，这样的玩具是肯定不行的啦。

在`Rust`的领域，我们当然有一大堆的优秀的库可以借用。
下面列一下使用[hyper](https://github.com/hyperium/hyper)来实现这个`Hello world`。

```rust
use std::convert::Infallible;

use hyper::server::conn::AddrStream;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server};

static DEFAULT_ADDR: &str = "127.0.0.1:5000";

async fn hello(_: Request<Body>) -> Result<Response<Body>, Infallible> {
    Ok(Response::new(Body::from("<h1>Hello World!</h1>")))
}

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // For every connection, we must make a `Service` to handle all
    // incoming HTTP requests on said connection.
    let make_svc = make_service_fn(|socket: &AddrStream| {
        // This is the `Service` that will handle the connection.
        // `service_fn` is a helper to convert a function that
        // returns a Response into a `Service`.
        let remote_addr = socket.remote_addr();
        async move {
            Ok::<_, Infallible>(service_fn(move |req: Request<Body>| {
                println!("handle conn from {:?}", remote_addr);
                hello(req)
            }))
        }
    });

    let addr = DEFAULT_ADDR.parse().expect("parse addr failed");

    let server = Server::bind(&addr).serve(make_svc);

    println!("Listening on http://{}", addr);

    server.await?;

    Ok(())
}

```

## 结语

本文尝试使用Rust构建一个简单的Hello world服务程序。
