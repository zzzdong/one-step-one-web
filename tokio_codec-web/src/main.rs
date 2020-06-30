use std::collections::HashMap;

use bytes::{Buf, BufMut, BytesMut};
use futures_util::sink::SinkExt;
use futures_util::stream::StreamExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::prelude::*;

use tokio_util::codec::{Decoder, Encoder, FramedRead, FramedWrite};

const REQUEST_LINE_PART_NUM: usize = 3;
const DEFAULT_ADDR: &str = "127.0.0.1:5000";
static HTTP_VERSION_1_1: &str = "HTTP/1.1";
static HEADER_CONTENT_LENGTH: &str = "Content-Length";

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

async fn handle_conn(mut socket: TcpStream) -> Result<(), std::io::Error> {
    println!("accept new connection from {:?}", socket.peer_addr());

    let (r_part, w_part) = socket.split();

    let reader = FramedRead::new(r_part, RequestDecoder::default());
    let mut writer = FramedWrite::new(w_part, ResponseEncoder::default());

    if let (Some(req), _decoder) = reader.into_future().await {
        println!("got request: {:?}", req);
        let mut resp = Response::ok();
        resp.set_body("<h1>Hello world!</h1>");
        if let Err(e) = writer.send(resp).await {
            println!("send resp failed, {:?}", e);
        }
    } else {
        println!("get request failed...");
    }

    Ok(())
}

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

#[derive(Debug, Clone, Default)]
struct ResponseEncoder;

impl Encoder<Response> for ResponseEncoder {
    type Error = std::io::Error;

    fn encode(&mut self, item: Response, dst: &mut BytesMut) -> Result<(), Self::Error> {
        item.write_response(dst)
    }
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
                                .map_err(|_e| error_message("content-length error"))?;
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
