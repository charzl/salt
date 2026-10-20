"""
Direct call executor module
"""

import salt.utils.secret


def execute(opts, data, func, args, kwargs):
    """
    Directly calls the given function with arguments
    """
    with salt.utils.secret.unmask_values_for_job((data or {}).get("fun")):
        return func(*args, **kwargs)
