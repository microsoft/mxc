namespace Microsoft.Mxc.Diplomat;

public enum MxcDiplomatErrorCode : int
{
    MalformedRequest = 0,
    UnsupportedContainment = 1,
    UnsupportedPhase = 2,
    BackendUnavailable = 3,
    MalformedId = 4,
    StaleId = 5,
    NotProvisioned = 6,
    NotStarted = 7,
    AlreadyStarted = 8,
    AlreadyStopped = 9,
    PolicyValidation = 10,
    BackendError = 11,
    Panic = 12,
}