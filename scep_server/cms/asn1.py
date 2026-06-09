from asn1crypto.cms import CMSAttribute
from asn1crypto.core import ObjectIdentifier


class SCEPCMSAttributeType(ObjectIdentifier):
    """CMS + SCEP signed attribute OIDs."""

    _map = {
        # Standard PKCS#9 attributes used in CMS SignedData
        "1.2.840.113549.1.9.3": "content_type",
        "1.2.840.113549.1.9.4": "message_digest",
        "1.2.840.113549.1.9.5": "signing_time",
        # SCEP attributes
        "2.16.840.1.113733.1.9.2": "message_type",
        "2.16.840.1.113733.1.9.3": "pki_status",
        "2.16.840.1.113733.1.9.4": "fail_info",
        "2.16.840.1.113733.1.9.5": "sender_nonce",
        "2.16.840.1.113733.1.9.6": "recipient_nonce",
        "2.16.840.1.113733.1.9.7": "transaction_id",
    }


CMSAttribute._fields = [
    ("type", SCEPCMSAttributeType),
    ("values", None),
]
