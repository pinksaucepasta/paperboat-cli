// Package privateproxyconfig deliberately configures only PAC autoconfiguration.
// It never enables WPAD or accepts a network PAC URL.
//
// On macOS it updates every active networksetup service and preserves each
// service's prior PAC URL and enabled state. On Windows the caller must provide
// a registry backend already bound to the current interactive user's WinINET
// Internet Settings key; machine-wide and SYSTEM-profile mutation is rejected.
// On Linux only a discoverable GNOME desktop session with a user D-Bus is
// supported through gsettings. Other desktops return ErrUnsupported.
package privateproxyconfig
