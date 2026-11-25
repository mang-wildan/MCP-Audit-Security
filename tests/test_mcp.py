import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


class MCPTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_stdio(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'web').mkdir()
            (root / 'web' / 'photo.png').write_text('<?php eval($_POST["SECRET"]);')
            config = root / 'config.json'
            config.write_text(json.dumps({'sites': {'demo': {'webroot': str(root / 'web')}}}))
            params = StdioServerParameters(command=sys.executable,
                args=['-m', 'mcp_audit_security.server'], env={**os.environ, 'MCP_AUDIT_CONFIG': str(config)})
            async with stdio_client(params) as (reader, writer):
                async with ClientSession(reader, writer) as session:
                    await session.initialize()
                    tools = await session.list_tools()
                    self.assertEqual({x.name for x in tools.tools}, {'host_inventory', 'persistence_audit', 'web_integrity', 'payload_scan', 'log_timeline'})
                    response = await session.call_tool('payload_scan', {'site_id': 'demo'})
                    self.assertFalse(response.isError)
                    self.assertIn('PHP_DYNAMIC_EXEC', str(response))
                    self.assertNotIn('SECRET', str(response))
                    denied = await session.call_tool('web_integrity', {'site_id': '../outside'})
                    self.assertTrue(denied.isError)


if __name__ == '__main__':
    unittest.main()
