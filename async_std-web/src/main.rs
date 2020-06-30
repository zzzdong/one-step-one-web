use std::collections::HashMap;


use async_std::io::{self, BufReader, BufWriter, Result};
use async_std::net::{TcpListener, TcpStream};
use async_std::prelude::*;
use async_std::task;

static DEFAULT_ADDR: &str = "127.0.0.1:5000";
static HTTP_VERSION_1_1: &str = "HTTP/1.1";
static HEADER_TRANSFER_ENCODING: &str = "Transfer-Encoding";
static HEADER_CONTENT_LENGTH: &str = "Content-Length";
static HEADER_CHUNKED: &str = "chunked";

const REQUEST_LINE_PART_NUM: usize = 3;
const STATUS_LINE_PART_NUM: usize = 3;


fn main() -> Result<()> {
    let mut addr = DEFAULT_ADDR;

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


async fn process(stream: TcpStream) -> Result<()> {
    println!("Accepted from: {}", stream.peer_addr()?);

    let mut conn = HttpConn::new(stream);

    let request = conn.read_request().await?;

    println!("income request: {:?}", request);

    let mut rsp = Response::new(200, "OK");

    rsp.set_body(b"<h1>Hello, world</h1>");

    conn.write_response(&rsp).await?;

    Ok(())
}

struct HttpConn {
    reader: BufReader<TcpStream>,
    writer: BufWriter<TcpStream>,
}

impl HttpConn {
    fn new(socket: TcpStream) -> HttpConn {
        let reader = BufReader::new(socket.clone());
        let writer = BufWriter::new(socket);

        HttpConn { reader, writer }
    }

    async fn read_request(&mut self) -> Result<Request> {
        Request::read_from(&mut self.reader).await
    }

    async fn write_request(&mut self, req: &Request) -> Result<()> {
        req.write_to(&mut self.writer).await?;
        self.writer.flush().await?;
        Ok(())
    }

    async fn read_response(&mut self) -> Result<Response> {
        Response::read_from(&mut self.reader).await
    }

    async fn write_response(&mut self, rsp: &Response) -> Result<()> {
        rsp.write_to(&mut self.writer).await?;

        self.writer.flush().await?;

        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
struct Request {
    method: String,
    target: String,
    version: String,
    headers: Headers,
    body: Option<Vec<u8>>,
}

impl Request {
    fn new(method: &str, host: &str, path: &str) -> Request {
        let mut headers = Headers::new();

        headers.insert("Host", host);
        headers.insert("User-Agent", "stdthread-web");

        Request {
            method: method.to_string(),
            target: path.to_string(),
            version: HTTP_VERSION_1_1.to_string(),
            headers: headers,
            body: None,
        }
    }

    async fn read_from(reader: &mut BufReader<TcpStream>) -> Result<Request> {
        let (method, target, version) = Self::read_request_line(reader).await?;

        let headers = Self::read_header(reader).await?;

        Ok(Request {
            method,
            target,
            version,
            headers,
            ..Default::default()
        })
    }

    async fn read_request_line(reader: &mut BufReader<TcpStream>) -> Result<(String, String, String)> {
        let mut line = String::new();

        reader.read_line(&mut line).await?;

        let line = line.trim_end();

        let parts: Vec<&str> = line.splitn(3, ' ').collect();
        if parts.len() != REQUEST_LINE_PART_NUM {
            return Err(error_message("start line not ok"));
        }

        Ok((
            String::from(parts[0]),
            String::from(parts[1]),
            String::from(parts[2]),
        ))
    }

    async fn read_header(reader: &mut BufReader<TcpStream>) -> Result<Headers> {
        Headers::read_from(reader).await
    }

    async fn write_to(&self, writer: &mut BufWriter<TcpStream>) -> Result<()> {
        self.write_request_line(writer).await?;
        self.write_headers(writer).await?;
        self.write_empty_line(writer).await?;

        Ok(())
    }

    async fn write_request_line(&self, writer: &mut BufWriter<TcpStream>) -> Result<()> {
        let line = format!("{} {} {}", self.method, self.target, self.version);
        write_crlf_line(writer, &line).await
    }

    async fn write_headers(&self, writer: &mut BufWriter<TcpStream>) -> Result<()> {
        self.headers.write_to(writer).await
    }

    async fn write_empty_line(&self, writer: &mut BufWriter<TcpStream>) -> Result<()> {
        write_crlf_line(writer, "").await?;
        Ok(())
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

    async fn read_from(reader: &mut BufReader<TcpStream>) -> Result<Response> {
        let (version, status_code, status_text) = Self::read_status_line(reader).await?;

        let mut rsp = Response::new(status_code, &status_text);
        rsp.version = version;

        let headers = Self::read_header(reader).await?;
        rsp.headers = headers;

        rsp.read_body(reader).await?;

        Ok(rsp)
    }

    async fn read_status_line(reader: &mut BufReader<TcpStream>) -> Result<(String, u16, String)> {
        let mut line = String::new();

        reader.read_line(&mut line).await?;

        let line = line.trim_end();

        let parts: Vec<&str> = line.splitn(3, ' ').collect();
        if parts.len() != STATUS_LINE_PART_NUM {
            return Err(error_message("status line not ok"));
        }

        let status_code = parts[1]
            .parse::<u16>()
            .map_err(|e| error_message(&format!("parse status code failed, {:?}", e)))?;

        Ok((String::from(parts[0]), status_code, String::from(parts[2])))
    }

    async fn read_header(reader: &mut BufReader<TcpStream>) -> Result<Headers> {
        Headers::read_from(reader).await
    }

    async fn read_body(&mut self, reader: &mut BufReader<TcpStream>) -> Result<()> {
        if let Some(length) = self.headers.get(HEADER_CONTENT_LENGTH) {
            if length.len() != 1 {
                return Err(error_message("Content-Length header not ok"));
            }

            let length = length[0]
                .parse::<usize>()
                .map_err(|e| error_message(&format!("parse Content-Length failed, {:?}", e)))?;

            return self.read_lengthed_body(length, reader).await;
        }

        if let Some(chunked) = self.headers.get(HEADER_TRANSFER_ENCODING) {
            if chunked.len() != 1 {
                return Err(error_message("Transfer-Encoding header not ok"));
            }

            if chunked[0] != HEADER_CHUNKED {
                return Err(error_message("Transfer-Encoding is not chunked"));
            }

            return self.read_chunked_body(reader).await;
        }

        Err(error_message("Can not read body"))
    }

    async fn read_lengthed_body(
        &mut self,
        length: usize,
        reader: &mut BufReader<TcpStream>,
    ) -> Result<()> {
        println!("try read body, {}", length);

        // let mut body = Vec::with_capacity(length);

        let mut buf = vec![0; length];
        reader.read_exact(&mut buf).await?;

        self.body = Some(buf);

        Ok(())
    }

    async fn read_chunked_body(&mut self, reader: &mut BufReader<TcpStream>) -> Result<()> {
        let mut body = Vec::new();

        loop {
            let mut line = String::new();
            reader.read_line(&mut line).await?;
            let line = line.trim_end();

            let chunk_size = usize::from_str_radix(&line, 16)
                .map_err(|e| error_message(&format!("parse chunked len failed, {:?}", e)))?;

            // read chunk into body
            let mut buf = vec![0; chunk_size];
            reader.read_exact(&mut buf).await?;
            body.extend_from_slice(&buf);

            let mut crlf = [0; 2];
            reader.read_exact(&mut crlf).await?;
            if &crlf != b"\r\n" {
                println!("crlf: {:?}", crlf);
                return Err(error_message("chunk not end with CRLF"));
            }

            if chunk_size == 0 {
                break;
            }
        }

        self.body = Some(body);

        Ok(())
    }

    async fn write_to(&self, writer: &mut BufWriter<TcpStream>) -> Result<()> {
        self.write_status_line(writer).await?;

        self.write_headers(writer).await?;

        self.write_connection_close(writer).await?;

        self.write_content_length(writer).await?;

        self.write_empty_line(writer).await?;

        self.write_body(writer).await?;

        Ok(())
    }

    async fn write_status_line(&self, writer: &mut BufWriter<TcpStream>) -> Result<()> {
        let mut version: &str = &self.version;
        if version.is_empty() {
            version = HTTP_VERSION_1_1;
        }

        let status_line = format!("{} {} {}", version, self.status_code, self.status_text);

        write_crlf_line(writer, &status_line).await?;

        Ok(())
    }

    async fn write_headers(&self, writer: &mut BufWriter<TcpStream>) -> Result<()> {
        self.headers.write_to(writer).await?;

        Ok(())
    }

    async fn write_connection_close(&self, writer: &mut BufWriter<TcpStream>) -> Result<()> {
        write_crlf_line(writer, "Connection: Close").await
    }

    async fn write_content_length(&self, writer: &mut BufWriter<TcpStream>) -> Result<()> {
        let mut length: usize = 0;
        if let Some(ref body) = self.body {
            length = body.len();
        }
        let line = format!("{}: {}", HEADER_CONTENT_LENGTH, length);
        write_crlf_line(writer, &line).await?;

        Ok(())
    }

    async fn write_empty_line(&self, writer: &mut BufWriter<TcpStream>) -> Result<()> {
        write_crlf_line(writer, "").await?;
        Ok(())
    }

    async fn write_body(&self, writer: &mut BufWriter<TcpStream>) -> Result<()> {
        if let Some(ref body) = self.body {
            writer.write(body).await?;
        }

        Ok(())
    }
}

impl Default for Response {
    fn default() -> Self {
        Response::ok()
    }
}

fn error_message(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Other, msg)
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

    async fn read_from(reader: &mut BufReader<TcpStream>) -> Result<Headers> {
        let mut headers: HashMap<String, Vec<String>> = HashMap::new();

        loop {
            let mut line = String::new();

            reader.read_line(&mut line).await?;

            let line = line.trim_end();

            if line.is_empty() {
                break;
            }

            let parts: Vec<&str> = line.splitn(2, ':').collect();
            if parts.len() != 2 {
                return Err(error_message("header line not ok"));
            }

            let key = parts[0].to_string();
            let value = parts[1].trim_start().to_string();

            headers
                .entry(key)
                .and_modify(|values| values.push(value.clone()))
                .or_insert(vec![value]);
        }

        let headers = Headers { inner: headers };

        Ok(headers)
    }

    async fn write_to(&self, writer: &mut BufWriter<TcpStream>) -> Result<()> {
        for (k, values) in &self.inner {
            for v in values {
                let line = format!("{}: {}", k, v);
                write_crlf_line(writer, &line).await?;
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

async fn write_crlf_line(writer: &mut BufWriter<TcpStream>, line: &str) -> Result<()> {
    writer.write(line.as_bytes()).await?;
    writer.write(b"\r\n").await?;
    Ok(())
}