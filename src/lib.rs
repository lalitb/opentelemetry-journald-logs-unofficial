use async_trait::async_trait;
use libc::{c_int, c_void};
use opentelemetry::logs::AnyValue;
use std::ffi::CString;
use std::fmt::Debug;

use opentelemetry::logs::LogError;
use opentelemetry_sdk::export::logs::{LogData, LogExporter};

use opentelemetry::logs::Severity;

extern "C" {
    fn sd_journal_sendv(iov: *const libc::iovec, n: libc::c_int) -> libc::c_int;
}

#[derive(Debug)]
pub struct JournaldLogExporter {
    identifier: CString,
    message_size_limit: usize,
}

impl JournaldLogExporter {
    pub fn new(identifier: &str, message_size_limit: usize) -> Self {
        JournaldLogExporter {
            identifier: CString::new(identifier).unwrap(),
            message_size_limit,
        }
    }

    fn send_to_journald(&self, iovecs: &[libc::iovec]) -> Result<(), std::io::Error> {
        let ret = unsafe { sd_journal_sendv(iovecs.as_ptr(), iovecs.len() as c_int) };
        if ret < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
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
                let attribute_str = format!("{}={}", key_str, value_str);
                let attribute = CString::new(attribute_str).unwrap();
                iovecs.push(libc::iovec {
                    iov_base: attribute.as_ptr() as *mut c_void,
                    iov_len: attribute.as_bytes().len(),
                });
                cstrings.push(attribute);
            }
        }

        let total_size: usize = iovecs.iter().map(|iov| iov.iov_len).sum();
        let size_exceeded = total_size > self.message_size_limit;

        // Try to send to journald regardless of the size
        let send_result = self.send_to_journald(&iovecs);

        if size_exceeded {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "Log message size {} exceeds the limit of {} bytes",
                    total_size, self.message_size_limit
                ),
            ));
        }

        send_result
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
