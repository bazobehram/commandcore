use serde_json::json;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use tokio::sync::{mpsc, Mutex};

#[derive(Clone)]
pub struct OutputSink {
    execution_id: String,
    tx: mpsc::Sender<serde_json::Value>,
    seq: Arc<AtomicU64>,
    capture: Arc<Mutex<crate::activity::Capture>>,
}

impl OutputSink {
    pub fn new(execution_id: impl Into<String>, tx: mpsc::Sender<serde_json::Value>) -> Self {
        Self {
            execution_id: execution_id.into(),
            tx,
            seq: Arc::new(AtomicU64::new(0)),
            capture: Arc::new(Mutex::new(crate::activity::Capture::default())),
        }
    }

    pub async fn preview(&self) -> serde_json::Value {
        self.capture.lock().await.value()
    }

    pub async fn send(&self, stream: &str, data: impl Into<String>) {
        let data = data.into();
        self.capture.lock().await.append(stream, &data);
        let mut offset = 0;
        while offset < data.len() {
            let mut end = (offset + 8192).min(data.len());
            while !data.is_char_boundary(end) {
                end -= 1;
            }
            let seq = self.seq.fetch_add(1, Ordering::Relaxed) + 1;
            if self
                .tx
                .send(json!({
                    "type": "job.output", "execution_id": self.execution_id,
                    "stream": stream, "seq": seq, "data": &data[offset..end],
                }))
                .await
                .is_err()
            {
                break;
            }
            offset = end;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn stalled_receiver_backpressures_output_and_preserves_unicode() {
        let (tx, mut rx) = mpsc::channel(1);
        let sink = OutputSink::new("fixture", tx);
        let original = "€".repeat(6000);
        let expected = original.clone();
        let producer = tokio::spawn(async move { sink.send("stdout", original).await });
        tokio::task::yield_now().await;
        assert!(!producer.is_finished());
        let mut observed = String::new();
        while let Some(frame) = rx.recv().await {
            let text = frame["data"].as_str().unwrap();
            assert!(text.len() <= 8192);
            observed.push_str(text);
        }
        producer.await.unwrap();
        assert_eq!(observed, expected);
    }
}
