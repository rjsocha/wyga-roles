from __future__ import annotations

DOCUMENTATION = """
    name: short
    type: stdout
    short_description: default output without the banners of include tasks
    description:
        - The default callback. With display_included_hosts set to false an
          include task (include_role, include_tasks) prints neither the
          included line nor its task banner.
    extends_documentation_fragment:
      - default_callback
      - result_format_callback
    requirements:
      - set as stdout in configuration
"""

from ansible.playbook.task_include import TaskInclude
from ansible.plugins.callback.default import CallbackModule as DefaultCallbackModule


class CallbackModule(DefaultCallbackModule):

    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = 'stdout'
    CALLBACK_NAME = 'short'

    def v2_runner_on_ok(self, result):
        if isinstance(result.task, TaskInclude) and not self.get_option('display_included_hosts'):
            return
        super().v2_runner_on_ok(result)
