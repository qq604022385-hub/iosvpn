// SPDX-License-Identifier: GPL-2.0-or-later
// Apple supplies the sandbox and entitlements. No Unix privilege elevation or
// user/group switch is attempted. Network configuration uses public NE APIs.
#include <utils/capabilities.h>
#include <unistd.h>
typedef struct { capabilities_t public; bool identity_unchanged; } ios_caps_t;
METHOD(capabilities_t, check, bool, ios_caps_t *this, u_int cap) { return cap == CAP_CHOWN; }
METHOD(capabilities_t, uid, uid_t, ios_caps_t *this) { return getuid(); }
METHOD(capabilities_t, gid, gid_t, ios_caps_t *this) { return getgid(); }
METHOD(capabilities_t, set_uid, void, ios_caps_t *this, uid_t uid) { this->identity_unchanged &= uid == getuid(); }
METHOD(capabilities_t, set_gid, void, ios_caps_t *this, gid_t gid) { this->identity_unchanged &= gid == getgid(); }
METHOD(capabilities_t, resolve_uid, bool, ios_caps_t *this, char *name) { return FALSE; }
METHOD(capabilities_t, resolve_gid, bool, ios_caps_t *this, char *name) { return FALSE; }
METHOD(capabilities_t, drop, bool, ios_caps_t *this) { return this->identity_unchanged; }
METHOD(capabilities_t, destroy, void, ios_caps_t *this) { free(this); }
capabilities_t *capabilities_create(void) {
    ios_caps_t *this;
    INIT(this, .public = { .keep = _check, .check = _check, .get_uid = _uid, .get_gid = _gid,
        .set_uid = _set_uid, .set_gid = _set_gid, .resolve_uid = _resolve_uid,
        .resolve_gid = _resolve_gid, .drop = _drop, .destroy = _destroy }, .identity_unchanged = TRUE);
    return &this->public;
}