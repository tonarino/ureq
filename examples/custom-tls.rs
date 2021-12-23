use std::io;
use std::net::TcpStream;
use std::sync::Arc;

use ureq::{Error, ReadWrite, TlsConnector};

pub fn main() -> Result<(), Error> {
    let agent = ureq::builder().tls_connector(Arc::new(PassThrough)).build();

    let _response = agent.get("https://example.com/").call();

    Ok(())
}

/// A pass-through tls connector that just uses the plain socket without any encryption.
/// This is not a good idea for production code.
struct PassThrough;

impl TlsConnector for PassThrough {
    fn connect(&self, _dns_name: &str, tcp_stream: TcpStream) -> Result<Box<dyn ReadWrite>, Error> {
        Ok(Box::new(CustomTlsStream(tcp_stream)))
    }
}

struct CustomTlsStream(TcpStream);

impl ReadWrite for CustomTlsStream {
    fn socket(&self) -> Option<&TcpStream> {
        Some(&self.0)
    }
}

impl io::Read for CustomTlsStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl io::Write for CustomTlsStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}
