"""browser_autofill - form-field history, saved profiles and card metadata.

Reads the Chromium ``Web Data`` store (``autofill`` form-field history,
address ``autofill_profiles`` / ``contact_info`` / ``local_addresses``,
and ``credit_cards`` / ``masked_credit_cards`` metadata) and Firefox
``formhistory.sqlite``.

Every field the user typed into a form is one row with its first / last
use and use count.  Card numbers and CVV / SSN-shaped values are never
output - only metadata (network, last four, expiry, use count).
Read-only and WAL-safe.  Pure standard library.
"""

__version__ = "0.1.0"
