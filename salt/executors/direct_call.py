"""
Direct call executor module
"""

import salt.utils.secret


def execute(opts, data, func, args, kwargs):
    """
    Directly calls the given function with arguments.

    While the job runs, ``pillar.get`` and friends return real values to code
    that calls them through ``__salt__`` without passing ``unmask``; repr() and
    logging of pillar data stay redacted. Jobs whose own function is a
    ``pillar.*`` function keep the masked default, since their return value is
    what the user sees.
    """
    with salt.utils.secret.unmask_values_for_job((data or {}).get("fun")):
        return func(*args, **kwargs)
