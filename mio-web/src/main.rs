use std::collections::HashMap;
use std::error::Error;
use std::io::{self, Read, Write};
use std::net::SocketAddr;

use bytes::{Buf, BufMut, BytesMut};
use mio::event::Source;
use mio::net::{TcpListener, TcpStream};
use mio::{Events, Interest, Poll, Registry, Token};

const BUF_SIZE: usize = 8 * 1024;
const EVENT_SIZE: usize = 1024;
const REQUEST_LINE_PART_NUM: usize = 3;
const DEFAULT_ADDR: &str = "127.0.0.1:5000";
static HTTP_VERSION_1_1: &str = "HTTP/1.1";
static HEADER_CONTENT_LENGTH: &str = "Content-Length";

fn main() -> Result<(), Box<dyn Error>> {
    let mut addr = DEFAULT_ADDR.to_string();
    let addr: SocketAddr = addr.parse()?;

    let mut poller = Poller::new()?;

    poller.listen(addr)?;

    poller.run_loop()?;

    Ok(())
}

enum State {
    Accepted(Vec<TcpStream>),
    Running,
    Done,
}

trait Pollee {
    fn on_readable(&mut self) -> io::Result<State>;
    fn on_writable(&mut self) -> io::Result<State>;
}

struct Poller {
    poller: Poll,
    last_token: usize,
    conns: HashMap<Token, Box<dyn Pollee>>,
}

impl Poller {
    fn new() -> io::Result<Self> {
        let poller = Poll::new()?;

        Ok(Poller {
            poller,
            conns: HashMap::new(),
            last_token: 0,
        })
    }

    fn listen(&mut self, addr: SocketAddr) -> io::Result<()> {
        let mut listener = Listener::bind(addr)?;

        let token = self.register(&mut listener, Interest::READABLE)?;

        self.conns.insert(token, Box::new(listener));

        Ok(())
    }

    fn register<S>(&mut self, source: &mut S, interests: Interest) -> io::Result<Token>
    where
        S: Source + ?Sized,
        S: Pollee,
    {
        let token = Token(self.last_token);
        self.poller.registry().register(source, token, interests)?;

        self.last_token += 1;

        Ok(token)
    }

    fn run_loop(&mut self) -> io::Result<()> {
        let mut events = Events::with_capacity(EVENT_SIZE);

        loop {
            self.poller.poll(&mut events, None)?;

            let mut to_removed = Vec::new();
            let mut new_conns = Vec::new();

            for event in &events {
                let token = event.token();
                let stream = { self.conns.get_mut(&token).unwrap() };

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
}

impl std::fmt::Debug for Poller {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Poller").finish()
    }
}

struct Listener {
    inner: TcpListener,
}

impl Listener {
    fn bind(addr: SocketAddr) -> io::Result<Self> {
        let listener = TcpListener::bind(addr)?;
        Ok(Listener { inner: listener })
    }
}

impl Pollee for Listener {
    fn on_readable(&mut self) -> io::Result<State> {
        let mut conns = Vec::new();

        loop {
            let (conn, addr) = match self.inner.accept() {
                Ok((conn, addr)) => (conn, addr),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    // when block, there is no more socket to accept.
                    break;
                }
                Err(e) => return Err(e),
            };

            println!("Accepted connection from: {}", addr);
            conns.push(conn);
        }

        Ok(State::Accepted(conns))
    }

    fn on_writable(&mut self) -> io::Result<State> {
        Ok(State::Running)
    }
}

impl Source for Listener {
    fn register(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        self.inner.register(registry, token, interests)
    }

    fn reregister(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        self.inner.reregister(registry, token, interests)
    }

    fn deregister(&mut self, registry: &Registry) -> io::Result<()> {
        self.inner.deregister(registry)
    }
}

#[derive(Debug)]
struct HttpConn {
    stream: TcpStream,
    r_buf: BytesMut,
    w_buf: BytesMut,
    req_codec: RequestCodec,
    finished: bool,
}

impl HttpConn {
    fn new(stream: TcpStream) -> Self {
        HttpConn {
            stream,
            r_buf: BytesMut::new(),
            w_buf: BytesMut::new(),
            req_codec: RequestCodec::default(),
            finished: false,
        }
    }

    fn write(&mut self, data: &[u8]) -> io::Result<()> {
        self.w_buf.put(data);

        self.flush()?;

        Ok(())
    }

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

    fn set_finished(&mut self) {
        self.finished = true;
    }
}

impl Pollee for HttpConn {
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
                // self.write(&b"HTTP/1.1 200 OK\r\nConnection: Close\r\nContent-Length: 22\r\n\r\n<h1>Hello, world!</h1>"[..])?;
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
}

impl Source for HttpConn {
    fn register(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        self.stream.register(registry, token, interests)
    }

    fn reregister(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        self.stream.reregister(registry, token, interests)
    }

    fn deregister(&mut self, registry: &Registry) -> io::Result<()> {
        self.stream.deregister(registry)
    }
}

trait Codec {
    type Item;

    fn encode(&mut self, item: &Self::Item, buf: &mut BytesMut) -> io::Result<()>;
    fn decode(&mut self, buf: &mut BytesMut) -> io::Result<Option<Self::Item>>;
}

#[derive(Debug, Clone, PartialEq)]
enum RequestState {
    RequestLine,
    Headers,
    Body(BodyMode),
    Done,
}

impl Default for RequestState {
    fn default() -> Self {
        RequestState::RequestLine
    }
}

#[derive(Debug, Clone, PartialEq)]
enum BodyMode {
    None,
    Lengthed(usize),
    Chunked,
}

#[derive(Debug, Clone, Default)]
struct Request {
    method: String,
    target: String,
    version: String,
    headers: Headers,
    body: Option<Vec<u8>>,
    state: RequestState,
}

impl Request {
    fn parse_request_line(&mut self, buf: &mut BytesMut) -> io::Result<Option<usize>> {
        let len = buf.len();

        match read_crlf_line(buf, 0, len) {
            Some((line, offset)) => {
                let line = line.trim_end();

                let parts: Vec<&str> = line.splitn(3, ' ').collect();
                if parts.len() != REQUEST_LINE_PART_NUM {
                    return Err(error_message("start line not ok"));
                }

                self.method = parts[0].to_string();
                self.target = parts[1].to_string();
                self.version = parts[2].to_string();

                buf.advance(offset);

                return Ok(Some(offset));
            }
            None => {
                return Ok(None);
            }
        }
    }

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
}

#[derive(Debug, Clone, Default)]
struct RequestCodec(Request);

impl Codec for RequestCodec {
    type Item = Request;

    fn encode(&mut self, item: &Self::Item, buf: &mut BytesMut) -> io::Result<()> {
        unimplemented!()
    }

    fn decode(&mut self, buf: &mut BytesMut) -> io::Result<Option<Self::Item>> {
        match self.0.parse_request(buf)? {
            Some(_) if self.0.state == RequestState::Done => {
                let req = Request::default();
                let req = std::mem::replace(&mut self.0, req);
                return Ok(Some(req));
            }
            _ => return Ok(None),
        }
    }
}
#[derive(Debug, Clone)]
struct Response {
    version: String,
    status_code: u16,
    status_text: String,
    headers: Headers,
    body: Option<Vec<u8>>,
}

impl Response {
    fn new(status_code: u16, status_text: &str) -> Response {
        Response {
            version: HTTP_VERSION_1_1.to_string(),
            status_code,
            status_text: status_text.to_string(),
            headers: Headers::new(),
            body: None,
        }
    }

    fn ok() -> Response {
        Self::new(200, "OK")
    }

    fn set_body(&mut self, body: impl AsRef<[u8]>) {
        self.body = Some(body.as_ref().to_vec());
    }

    fn write_response(&self, buf: &mut BytesMut) -> io::Result<()> {
        self.write_status_line(buf)?;

        self.write_headers(buf)?;

        self.write_connection_close(buf)?;

        self.write_content_length(buf)?;

        self.write_empty_line(buf)?;

        self.write_body(buf)?;

        Ok(())
    }

    fn write_status_line(&self, buf: &mut BytesMut) -> io::Result<()> {
        let mut version: &str = &self.version;
        if version.is_empty() {
            version = HTTP_VERSION_1_1;
        }

        let status_line = format!("{} {} {}", version, self.status_code, self.status_text);

        write_crlf_line(buf, &status_line)?;

        Ok(())
    }

    fn write_headers(&self, buf: &mut BytesMut) -> io::Result<()> {
        self.headers.write_to(buf)?;

        Ok(())
    }

    fn write_connection_close(&self, buf: &mut BytesMut) -> io::Result<()> {
        write_crlf_line(buf, "Connection: Close")
    }

    fn write_content_length(&self, buf: &mut BytesMut) -> io::Result<()> {
        let mut length: usize = 0;
        if let Some(ref body) = self.body {
            length = body.len();
        }
        let line = format!("{}: {}", HEADER_CONTENT_LENGTH, length);
        write_crlf_line(buf, &line)?;

        Ok(())
    }

    fn write_empty_line(&self, buf: &mut BytesMut) -> io::Result<()> {
        write_crlf_line(buf, "")?;
        Ok(())
    }

    fn write_body(&self, buf: &mut BytesMut) -> io::Result<()> {
        if let Some(ref body) = self.body {
            buf.put(body.as_slice());
        }

        Ok(())
    }
}

impl Default for Response {
    fn default() -> Self {
        Response::ok()
    }
}

#[derive(Debug, Clone, Default)]
struct ResponseCodec;

impl Codec for ResponseCodec {
    type Item = Response;

    fn encode(&mut self, item: &Self::Item, buf: &mut BytesMut) -> io::Result<()> {
        item.write_response(buf)
    }

    fn decode(&mut self, buf: &mut BytesMut) -> io::Result<Option<Self::Item>> {
        unimplemented!()
    }
}

#[derive(Debug, Clone)]
struct Headers {
    inner: HashMap<String, Vec<String>>,
}

impl Headers {
    fn new() -> Headers {
        Headers {
            inner: HashMap::new(),
        }
    }

    fn get<'a>(&'a self, key: &str) -> Option<&'a std::vec::Vec<std::string::String>> {
        self.inner.get(key)
    }

    fn insert(&mut self, key: &str, value: &str) {
        self.inner
            .entry(key.to_string())
            .and_modify(|v| v.push(value.to_string()))
            .or_insert(vec![value.to_string()]);
    }

    fn parse_headers(&mut self, buf: &mut BytesMut) -> io::Result<Option<usize>> {
        let mut offset = 0;
        let len = buf.len();

        self.inner.clear();

        loop {
            match read_crlf_line(buf, offset, len) {
                Some((line, off)) => {
                    let line = line.trim_end();
                    if line.is_empty() {
                        offset += off;
                        break;
                    }

                    let parts: Vec<&str> = line.splitn(2, ':').collect();
                    if parts.len() != 2 {
                        return Err(error_message("header line not ok"));
                    }

                    let key = parts[0].to_string();
                    let value = parts[1].trim_start().to_string();

                    self.inner
                        .entry(key)
                        .and_modify(|values| values.push(value.clone()))
                        .or_insert(vec![value]);

                    offset += off;
                }

                None => {
                    return Ok(None);
                }
            }
        }

        buf.advance(offset);

        return Ok(Some(offset));
    }

    fn write_to(&self, buf: &mut BytesMut) -> io::Result<()> {
        for (k, values) in &self.inner {
            for v in values {
                let line = format!("{}: {}", k, v);
                write_crlf_line(buf, &line)?;
            }
        }

        Ok(())
    }
}

impl Default for Headers {
    fn default() -> Self {
        Headers::new()
    }
}

fn read_crlf_line(buf: &[u8], start: usize, len: usize) -> Option<(String, usize)> {
    if start >= len {
        return None;
    }

    for i in start..len {
        if buf[i] == b'\n' {
            if i > 0 && buf[i - 1] == b'\r' {
                let line = String::from_utf8_lossy(&buf[start..i]).to_string();
                return Some((line, i - start + 1));
            }
        }
    }

    None
}

fn write_crlf_line(buf: &mut BytesMut, line: &str) -> io::Result<()> {
    buf.put(line.as_bytes());
    buf.put(&b"\r\n"[..]);
    Ok(())
}

fn error_message(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Other, msg)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parse_headers() {
        let input = b"Content-Length: 100\r\nContent-Type: text/HTML\r\n\r\n";

        let mut input = BytesMut::from(&input[..]);

        let mut headers = Headers::default();
        headers.parse_headers(&mut input).unwrap();

        println!("headers=>{:?}", headers);
    }
}
