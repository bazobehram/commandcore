"""Fail-closed source regression for native draft consumption order."""
from pathlib import Path
import unittest

SRC = Path("/tmp/cc-native-root-0371549/agent/rust/src/collaboration.rs")

class DraftOrderTest(unittest.TestCase):
    def test_permit_before_draft_consumption(self):
        body = SRC.read_text().split("async fn deliver(args:&Value)->Result<Value>{", 1)[1]
        body = body.split("async fn ", 1)[0]
        verify = body.index("verify_optional_delivery_permit(args,draft_id,&data)?;")
        remove = body.index("fs::remove_file(&path)?;")
        approval = body.index("local_approval(&s,message,title).await?")
        self.assertLess(verify, remove)
        self.assertLess(remove, approval)

if __name__=="__main__":
    unittest.main()
