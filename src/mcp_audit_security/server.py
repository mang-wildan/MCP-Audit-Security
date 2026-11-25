"""stdio only. Config loaded once before accepting MCP traffic."""
import os
import sys
from mcp.server.fastmcp import FastMCP
from .core import Audit, ConfigError, load_config


def create_server(config):
    audit = Audit(config)
    server = FastMCP('MCP Audit Security')
    annotations = {'readOnlyHint': True, 'destructiveHint': False,
                   'idempotentHint': True, 'openWorldHint': False}
    for name in ('host_inventory', 'persistence_audit', 'web_integrity', 'payload_scan', 'log_timeline'):
        server.tool(name=name, annotations=annotations)(getattr(audit, name))
    return server


def main():
    try:
        config = load_config(os.environ.get('MCP_AUDIT_CONFIG'))
    except ConfigError:
        print('MCP_AUDIT_CONFIG required: valid, accessible absolute JSON config.', file=sys.stderr)
        raise SystemExit(2) from None
    create_server(config).run(transport='stdio')


if __name__ == '__main__':
    main()
