from ansible.module_utils.common.collections import is_sequence

def TList(value):
    return is_sequence(value)

class TestModule:
    def tests(self):
        return {
            'TList': TList
        }
