from pathlib import Path
import unittest

class MCPPermitBoundary(unittest.TestCase):
    def test_untrusted_delivery_permit_rejected_before_dispatch(self):
        source = (Path(__file__).resolve().parents[1] / 'apps/server/commandcore_server/tools.py').read_text()
        guard = 'if name == "agents.deliver" and "signed_permit" in forwarded:'
        self.assertEqual(source.count(guard), 1)
        rejection = source.index('"permit_source_not_trusted"', source.index(guard))
        dispatch = source.index('result = await self.agents.dispatch(', rejection)
        self.assertLess(rejection, dispatch)

if __name__ == '__main__': unittest.main()
