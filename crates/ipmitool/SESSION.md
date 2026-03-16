# Session Notes

## IPMI v1.5 auth code: payload length byte is NOT included

The IPMI v1.5 spec section 22.17.1 describes the auth code "Data" field
ambiguously. The C `ipmitool` 1.8.19 does **not** include the payload
length byte in the MD5 auth code hash — confirmed via wire capture
comparison against a Supermicro BMC (serial WM216S001257). The correct
formula for all messages (pre-session and in-session) is:

    MD5(password_pad16 || session_id_LE || ipmi_msg || session_seq_LE || password_pad16)

This contradicts some readings of the spec but matches the C reference
implementation and produces correct auth codes accepted by the BMC.

## Activate Session response format

The response data layout (after completion code) is:

    [0]    Auth type
    [1..5] Session ID (LE, 4 bytes)
    [5..9] Initial message sequence number (LE, 4 bytes)
    [9]    Maximum privilege level (optional)

There is **no** separate privilege-level byte between auth type and
session ID. The original plan incorrectly placed a privilege byte at
offset [1], causing the session ID to be read from the wrong offset.
