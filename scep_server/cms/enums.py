from enum import Enum


class MessageType(Enum):
    CertRep = "3"
    RenewalReq = "17"
    UpdateReq = "18"
    PKCSReq = "19"
    CertPoll = "20"
    GetCert = "21"
    GetCRL = "22"


class PKIStatus(Enum):
    SUCCESS = "0"
    FAILURE = "2"
    PENDING = "3"


class FailInfo(Enum):
    BadAlg = "0"
    BadMessageCheck = "1"
    BadRequest = "2"
    BadTime = "3"
    BadCertId = "4"
