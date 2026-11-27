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

    async def test_triage_registered_only_when_configured(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'web').mkdir()
            (root / 'web' / 'x.php').write_text('<?php eval($_POST["x"]);')
            config = root / 'config.json'
            config.write_text(json.dumps({'sites': {'demo': {'webroot': str(root / 'web')}},
                'triage': {'model': 'typesafe/jev-1.14', 'api_key_file': str(root / 'missing-key')}}))
            params = StdioServerParameters(command=sys.executable,
                args=['-m', 'mcp_audit_security.server'], env={**os.environ, 'MCP_AUDIT_CONFIG': str(config)})
            async with stdio_client(params) as (reader, writer):
                async with ClientSession(reader, writer) as session:
                    await session.initialize()
                    tools = await session.list_tools()
                    self.assertIn('payload_triage', {x.name for x in tools.tools})
                    triage_tool = next(x for x in tools.tools if x.name == 'payload_triage')
                    self.assertTrue(triage_tool.annotations.openWorldHint)
                    self.assertFalse(triage_tool.annotations.idempotentHint)
                    response = await session.call_tool('payload_triage', {'site_id': 'demo'})
                    self.assertFalse(response.isError)
                    self.assertIn('api_key_unavailable', str(response))


if __name__ == '__main__':
    unittest.main()
