mod utils;

use async_trait::async_trait;
use libc::{c_int, c_void};
use opentelemetry::logs::AnyValue;
use std::ffi::CString;
use std::fmt::Debug;
use std::io::Write;

use opentelemetry::logs::LogError;
use opentelemetry_sdk::export::logs::{LogData, LogExporter};

use crate::utils::utils::send_fd_journald;
use crate::utils::utils::{create_sealable, seal_fully};
use opentelemetry::logs::Severity;
use std::io::Seek;
use std::io::Read;

extern "C" {
    fn sd_journal_sendv(iov: *const libc::iovec, n: libc::c_int) -> libc::c_int;
}

#[derive(Default)]
pub struct JournaldLogExporterBuilder {
    identifier: Option<String>,
    message_size_limit: Option<usize>,
    attribute_prefix: Option<String>,
}

impl JournaldLogExporterBuilder {
    pub fn identifier(mut self, identifier: &str) -> Self {
        self.identifier = Some(identifier.to_string());
        self
    }

    pub fn message_size_limit(mut self, message_size_limit: usize) -> Self {
        self.message_size_limit = Some(message_size_limit);
        self
    }

    pub fn attribute_prefix(mut self, attribute_prefix: Option<String>) -> Self {
        if let Some(prefix) = attribute_prefix {
            self.attribute_prefix = Some(prefix.to_uppercase());
        } else {
            self.attribute_prefix = None;
        }
        self
    }

    pub fn build(self) -> Result<JournaldLogExporter, &'static str> {
        let identifier = self.identifier.ok_or("Identifier is required")?;
        let message_size_limit = self
            .message_size_limit
            .ok_or("Message size limit is required")?;
        Ok(JournaldLogExporter {
            identifier: CString::new(identifier).map_err(|_| "Invalid identifier")?,
            message_size_limit,
            attribute_prefix: self.attribute_prefix,
        })
    }
}

#[derive(Debug)]
pub struct JournaldLogExporter {
    identifier: CString,
    message_size_limit: usize,
    attribute_prefix: Option<String>,
}

impl JournaldLogExporter {
    pub fn builder() -> JournaldLogExporterBuilder {
        JournaldLogExporterBuilder::default()
    }

    fn send_to_journald(&self, iovecs: &[libc::iovec]) -> Result<(), std::io::Error> {
        println!("Sending log to journald");
        let ret = unsafe { sd_journal_sendv(iovecs.as_ptr(), iovecs.len() as c_int) };
        if ret < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn send_large_log_to_journald(&self, payload: &[u8]) -> Result<(), std::io::Error> {
        println!("Sending large log to journald with payload size: {}", payload.len());
        use std::os::unix::prelude::AsRawFd;
    
        // Create sealable memfd
        let mut mem = create_sealable()?;
        println!("Created sealable memfd: {:?}", mem);
    
        // Write payload to memfd
        mem.write_all(payload)?;
        println!("Wrote payload to memfd: {:?}", String::from_utf8_lossy(payload));
    
        // Verify content written to memfd
        mem.flush()?;
        let mut verify_buf = vec![0; payload.len()];
        mem.seek(std::io::SeekFrom::Start(0))?;
        mem.read_exact(&mut verify_buf)?;
        println!("Verified content in memfd: {:?}", String::from_utf8_lossy(&verify_buf));
    
        // Seal memfd
        seal_fully(mem.as_raw_fd())?;
        println!("Sealed memfd");
    
        // Send fd to journald
        let result = send_fd_journald(mem.as_raw_fd(), "/run/systemd/journal/socket");
        println!("Sent fd to journald, result: {:?}", result);
    
        // Check to ensure the fd was sent
        if let Err(e) = &result {
            println!("Error sending fd to journald: {}", e);
        } else {
            println!("Successfully sent fd to journald");
        }
    
        // Ensure the memfd is not prematurely closed
        std::mem::forget(mem);
    
        result
    }

    fn send_log_to_journald(&self, log_data: &LogData) -> Result<(), std::io::Error> {
        let mut iovecs: Vec<libc::iovec> = Vec::new();
        let mut cstrings: Vec<CString> = Vec::new();

        // Add the SYSLOG_IDENTIFIER field
        let identifier_str = format!("SYSLOG_IDENTIFIER={}", self.identifier.to_str().unwrap());
        let identifier_field = CString::new(identifier_str).unwrap();
        iovecs.push(libc::iovec {
            iov_base: identifier_field.as_ptr() as *mut c_void,
            iov_len: identifier_field.as_bytes().len(),
        });
        cstrings.push(identifier_field);

        // Add the MESSAGE field
        if let Some(body) = &log_data.record.body {
            let formatted_body = format_any_value(body);
            let message_str = format!("MESSAGE={}", formatted_body);
            let message = CString::new(message_str).unwrap();
            iovecs.push(libc::iovec {
                iov_base: message.as_ptr() as *mut c_void,
                iov_len: message.as_bytes().len(),
            });
            cstrings.push(message);
        }

        // Add the PRIORITY field
        let priority_str = format!(
            "PRIORITY={}",
            get_priority(&log_data.record.severity_number.unwrap_or(Severity::Info))
        );
        let priority = CString::new(priority_str).unwrap();
        iovecs.push(libc::iovec {
            iov_base: priority.as_ptr() as *mut c_void,
            iov_len: priority.as_bytes().len(),
        });
        cstrings.push(priority);

        // Add other attributes
        if let Some(attr_list) = &log_data.record.attributes {
            for (key, value) in attr_list.iter() {
                let key_str = sanitize_field_name(key.as_str());
                let value_str = format_any_value(value);
                let attribute_str = if let Some(ref prefix) = self.attribute_prefix {
                    format!("{}{}={}", prefix, key_str, value_str)
                } else {
                    format!("{}={}", key_str, value_str)
                };
                let attribute = CString::new(attribute_str).unwrap();
                iovecs.push(libc::iovec {
                    iov_base: attribute.as_ptr() as *mut c_void,
                    iov_len: attribute.as_bytes().len(),
                });
                cstrings.push(attribute);
            }
        }

        let total_size: usize = iovecs.iter().map(|iov| iov.iov_len).sum();

        if total_size > self.message_size_limit {
            // If size exceeds limit, try sending as large log
            return self.send_large_log_to_journald(
                &iovecs
                    .iter()
                    .flat_map(|iov| unsafe {
                        std::slice::from_raw_parts(iov.iov_base as *const u8, iov.iov_len)
                    })
                    .copied()
                    .collect::<Vec<u8>>(),
            );
        } else {
            // Send normal log
            self.send_to_journald(&iovecs)
        }
    }
}

fn format_any_value(value: &AnyValue) -> String {
    match value {
        AnyValue::Int(v) => v.to_string(),
        AnyValue::Double(v) => v.to_string(),
        AnyValue::String(v) => v.to_string(),
        AnyValue::Boolean(v) => v.to_string(),
        AnyValue::Bytes(v) => format!("{:?}", v),
        AnyValue::ListAny(values) => {
            let elements: Vec<String> = values.iter().map(format_any_value).collect();
            format!("[{}]", elements.join(", "))
        }
        AnyValue::Map(map) => {
            let entries: Vec<String> = map
                .iter()
                .map(|(k, v)| format!("{}: {}", k, format_any_value(v)))
                .collect();
            format!("{{{}}}", entries.join(", "))
        }
    }
}

fn get_priority(severity: &Severity) -> i32 {
    match severity {
        Severity::Debug | Severity::Debug2 | Severity::Debug3 | Severity::Debug4 => 7, // debug
        Severity::Info | Severity::Info2 | Severity::Info3 | Severity::Info4 => 6,     // info
        Severity::Warn | Severity::Warn2 | Severity::Warn3 | Severity::Warn4 => 4,     // warning
        Severity::Error | Severity::Error2 | Severity::Error3 | Severity::Error4 => 3, // error
        Severity::Fatal | Severity::Fatal2 | Severity::Fatal3 | Severity::Fatal4 => 2, // critical
        _ => 5, // notice (default)
    }
}

#[async_trait]
impl LogExporter for JournaldLogExporter {
    async fn export(&mut self, batch: Vec<LogData>) -> Result<(), LogError> {
        let mut partial_failure = false;
        for log in batch {
            match self.send_log_to_journald(&log) {
                Ok(_) => (),
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::InvalidData {
                        partial_failure = true;
                    } else {
                        return Err(LogError::Other(Box::new(e)));
                    }
                }
            }
        }
        if partial_failure {
            return Err(LogError::from(
                "Some log messages exceeded the size limit and were not exported",
            ));
        }
        Ok(())
    }
}

fn sanitize_field_name(name: &str) -> String {
    name.chars()
        .map(|c| if c == '.' { '_' } else { c })
        .skip_while(|&c| c == '_')
        .filter(|&c| c == '_' || c.is_ascii_alphanumeric())
        .collect::<String>()
        .to_uppercase()
}
