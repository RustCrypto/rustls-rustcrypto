use std::{
    io::{self, ErrorKind, Read, Write},
    sync::mpsc::{Receiver, Sender, channel},
};

use bytes::{Buf, Bytes, BytesMut};

// The code is derived from: https://github.com/bmwill/memory-socket/blob/74110b18318c261e86d08aa53a7abe3e2a881538/src/lib.rs#L271-L405
pub struct MemorySocket {
    incoming: Receiver<Bytes>,
    outgoing: Sender<Bytes>,
    write_buffer: BytesMut,
    current_buffer: Option<Bytes>,
    seen_eof: bool,
}

impl MemorySocket {
    fn new(incoming: Receiver<Bytes>, outgoing: Sender<Bytes>) -> Self {
        Self {
            incoming,
            outgoing,
            write_buffer: BytesMut::new(),
            current_buffer: None,
            seen_eof: false,
        }
    }

    pub fn new_pair() -> (Self, Self) {
        let (a_tx, a_rx) = channel();
        let (b_tx, b_rx) = channel();
        let a = Self::new(a_rx, b_tx);
        let b = Self::new(b_rx, a_tx);

        (a, b)
    }
}

impl Read for MemorySocket {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut bytes_read = 0;

        loop {
            // If we've already filled up the buffer then we can return
            if bytes_read == buf.len() {
                return Ok(bytes_read);
            }

            match self.current_buffer {
                // We still have data to copy to `buf`
                Some(ref mut current_buffer) if current_buffer.has_remaining() => {
                    let bytes_to_read =
                        core::cmp::min(buf.len() - bytes_read, current_buffer.remaining());
                    debug_assert!(bytes_to_read > 0);

                    current_buffer
                        .take(bytes_to_read)
                        .copy_to_slice(&mut buf[bytes_read..(bytes_read + bytes_to_read)]);
                    bytes_read += bytes_to_read;
                }

                // Either we've exhausted our current buffer or we don't have one
                _ => {
                    // If we've read anything up to this point return the bytes read
                    if bytes_read > 0 {
                        return Ok(bytes_read);
                    }

                    self.current_buffer = match self.incoming.recv() {
                        Ok(buf) => Some(buf),

                        // The remote side hung up, if this is the first time we've seen EOF then
                        // we should return `Ok(0)` otherwise an UnexpectedEof Error
                        Err(_) => {
                            if self.seen_eof {
                                return Err(ErrorKind::UnexpectedEof.into());
                            } else {
                                self.seen_eof = true;
                                return Ok(0);
                            }
                        }
                    }
                }
            }
        }
    }
}

impl Write for MemorySocket {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_buffer.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if !self.write_buffer.is_empty() {
            self.outgoing
                .send(self.write_buffer.split().freeze())
                .map_err(|_| ErrorKind::BrokenPipe.into())
        } else {
            Ok(())
        }
    }
}
