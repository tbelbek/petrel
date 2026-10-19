// Mac-side Wi-Fi scanner: proves whether the board's raw frames actually reach the air.
//
// macOS has no CLI scanner any more (the `airport` binary is gone and `wdutil` needs sudo), but
// CoreWLAN works from a plain Swift script. Feed it a unique fake SSID from the board (e.g.
// `BSSID DELFYTEST`, or an AP-clone) and this is the ground truth for "is the TX on the air?".
//
// Usage: swift tools/mac_wifiscan.swift
//
// Notes:
//  - macOS caches scan results, so an SSID that stopped transmitting can linger for a while.
//    Treat "appeared" as proof and "still listed right after BEACONOFF" as cache.
//  - RSSI around -20/-30 means the board is right next to the Mac.
import Foundation
import CoreWLAN

guard let iface = CWWiFiClient.shared().interface() else {
    print("NO INTERFACE")
    exit(1)
}
// Usage: swift tools/mac_wifiscan.swift [SSID]
//
// Pass an SSID to do a *directed* scan. That distinction is the whole point: the broad scan is
// cached by macOS for ~15 s and comes back with only a handful of results, so an AP that just
// came up (a fake one the board started two seconds ago) is simply not in it - which is exactly
// how a 5 GHz pilot gets a false negative. A directed scan makes CoreWLAN actively probe for that
// name, and it retries for a few seconds in case the AP is still booting.
let want: String? = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : nil
var nets = Set<CWNetwork>()
if let w = want {
    for _ in 0..<4 {
        if let r = try? iface.scanForNetworks(withName: w) { nets = r }
        if !nets.isEmpty { break }
        Thread.sleep(forTimeInterval: 2.0)
    }
} else if let r = try? iface.scanForNetworks(withName: nil) {
    nets = r
}
guard !nets.isEmpty else {
    print("SCAN FAILED or nothing found")
    exit(1)
}
print("COUNT \(nets.count)")
for n in nets.sorted(by: { ($0.ssid ?? "") < ($1.ssid ?? "") }) {
    print("\(n.ssid ?? "<hidden>") | bssid \(n.bssid ?? "-") | ch \(n.wlanChannel?.channelNumber ?? 0) | rssi \(n.rssiValue)")
}
